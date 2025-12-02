use bytes::Bytes;
use http::{
    header::{HeaderMap, HeaderName, HeaderValue, HOST},
    Method, Request, Response,
    uri::Authority,
};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Incoming};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use once_cell::sync::Lazy;
use ratls_core::{ratls_connect, AttestationResult, Policy};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::Mutex;
use tokio::task;

#[napi(object)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

#[napi(object)]
pub struct JsAttestation {
    pub trusted: bool,
    pub tee_type: String,
    pub measurement: Option<String>,
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
}

impl From<AttestationResult> for JsAttestation {
    fn from(value: AttestationResult) -> Self {
        Self {
            trusted: value.trusted,
            tee_type: format!("{:?}", value.tee_type).to_lowercase(),
            measurement: value.measurement,
            tcb_status: value.tcb_status,
            advisory_ids: value.advisory_ids,
        }
    }
}

#[napi(object)]
pub struct JsHttpResponse {
    pub attestation: JsAttestation,
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<HeaderEntry>,
    pub body: Buffer,
}

#[napi(object)]
pub struct JsStreamingResponse {
    pub attestation: JsAttestation,
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<HeaderEntry>,
    pub stream_id: u32,
}

fn normalize_path(path: &str) -> String {
    if path.trim().is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}

async fn connect_helper(
    target_host: String,
    server_name: String,
) -> napi::Result<(
    TokioIo<ratls_core::platform::TlsStream<TcpStream>>,
    AttestationResult,
)> {
    // Use async DNS resolution instead of blocking to_socket_addrs
    let tcp_addr = lookup_host(&target_host)
        .await
        .map_err(|err| Error::from_reason(format!("invalid target host: {err}")))?
        .next()
        .ok_or_else(|| Error::from_reason("unable to resolve target host"))?;

    let tcp = TcpStream::connect(tcp_addr)
        .await
        .map_err(|err| Error::from_reason(format!("tcp connect failed: {err}")))?;

    ratls_connect(
        tcp,
        &server_name,
        Policy::default(),
        Some(vec!["http/1.1".into()]),
    )
    .await
    .map_err(|err| Error::from_reason(format!("ratls handshake failed: {err}")))
    .map(|(tls, attestation)| (TokioIo::new(tls), attestation))
}

fn default_host_header(target_host: &str, server_name: &str) -> String {
    target_host
        .parse::<Authority>()
        .map(|authority| match authority.port_u16() {
            Some(port) if port != 443 => authority.as_str().to_string(),
            _ => {
                let host = authority.host();
                if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host.to_string()
                }
            }
        })
        .unwrap_or_else(|_| server_name.to_string())
}

fn headers_to_map(headers: Vec<HeaderEntry>, default_host: &str) -> napi::Result<HeaderMap> {
    let mut map = HeaderMap::with_capacity(headers.len() + 1);
    let mut has_host = false;

    for HeaderEntry { name, value } in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| Error::from_reason(format!("Invalid header name '{name}': {e}")))?;
        let value = HeaderValue::from_str(&value)
            .map_err(|e| Error::from_reason(format!("Invalid header value for {name}: {e}")))?;
        has_host |= name == HOST;
        map.append(name, value);
    }

    if !has_host {
        let value = HeaderValue::from_str(default_host)
            .map_err(|e| Error::from_reason(format!("Invalid host value: {e}")))?;
        map.insert(HOST, value);
    }

    Ok(map)
}

fn build_hyper_request(
    method: String,
    path: String,
    headers: HeaderMap,
    body: Option<Buffer>,
) -> napi::Result<Request<Full<Bytes>>> {
    let method = Method::from_bytes(method.trim().as_bytes())
        .map_err(|e| Error::from_reason(format!("Invalid method: {e}")))?;

    let mut builder = Request::builder().method(method).uri(normalize_path(&path));

    for (name, value) in headers.iter() {
        builder = builder.header(name, value);
    }

    let body_bytes = match body {
        Some(b) => Bytes::from(b.to_vec()),
        None => Bytes::new(),
    };

    builder
        .body(Full::new(body_bytes))
        .map_err(|e| Error::from_reason(format!("Failed to build request: {e}")))
}

async fn dispatch_request(
    target_host: String,
    server_name: String,
    request: Request<Full<Bytes>>,
) -> napi::Result<(AttestationResult, Response<Incoming>)> {
    let (io, attestation) = connect_helper(target_host, server_name).await?;
    let (mut sender, conn) = http1::handshake(io)
        .await
        .map_err(|e| Error::from_reason(format!("HTTP handshake failed: {e}")))?;

    task::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Connection failed: {:?}", e);
        }
    });

    let res = sender
        .send_request(request)
        .await
        .map_err(|e| Error::from_reason(format!("HTTP request failed: {e}")))?;

    Ok((attestation, res))
}

fn extract_response_meta<B>(res: &Response<B>) -> (u16, String, Vec<HeaderEntry>) {
    let status = res.status().as_u16();
    let status_text = res.status().canonical_reason().unwrap_or("").to_string();
    let headers = res
        .headers()
        .iter()
        .map(|(k, v)| HeaderEntry {
            name: k.as_str().to_string(),
            value: v.to_str().unwrap_or("").to_string(),
        })
        .collect();
    (status, status_text, headers)
}

#[napi]
pub async fn http_request(
    target_host: String,
    server_name: String,
    method: String,
    path: String,
    headers: Vec<HeaderEntry>,
    body: Option<Buffer>,
) -> napi::Result<JsHttpResponse> {
    let default_host = default_host_header(&target_host, &server_name);
    let header_map = headers_to_map(headers, &default_host)?;
    let req = build_hyper_request(method, path, header_map, body)?;
    let (attestation, res) = dispatch_request(target_host, server_name, req).await?;
    let (status, status_text, response_headers) = extract_response_meta(&res);

    let collected = res
        .collect()
        .await
        .map_err(|e| Error::from_reason(format!("Failed to read body: {e}")))?;
    let body_vec = collected.to_bytes().to_vec();

    Ok(JsHttpResponse {
        attestation: attestation.into(),
        status,
        status_text,
        headers: response_headers,
        body: Buffer::from(body_vec),
    })
}

/// Idle timeout for streams - streams not accessed for this duration will be cleaned up
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

struct StreamState {
    incoming: Incoming,
    pending: Bytes,
    last_accessed: Instant,
}

static STREAMS: Lazy<Mutex<HashMap<u32, StreamState>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static STREAM_ID: AtomicU32 = AtomicU32::new(1);

/// Clean up idle streams that haven't been accessed within STREAM_IDLE_TIMEOUT
async fn cleanup_idle_streams() {
    let mut guard = STREAMS.lock().await;
    let now = Instant::now();
    guard.retain(|stream_id, state| {
        let idle_duration = now.duration_since(state.last_accessed);
        if idle_duration > STREAM_IDLE_TIMEOUT {
            eprintln!(
                "Cleaning up idle stream {} (idle for {:?})",
                stream_id, idle_duration
            );
            false
        } else {
            true
        }
    });
}

#[napi]
pub async fn http_stream_request(
    target_host: String,
    server_name: String,
    method: String,
    path: String,
    headers: Vec<HeaderEntry>,
    body: Option<Buffer>,
) -> napi::Result<JsStreamingResponse> {
    let default_host = default_host_header(&target_host, &server_name);
    let header_map = headers_to_map(headers, &default_host)?;
    let req = build_hyper_request(method, path, header_map, body)?;
    let (attestation, res) = dispatch_request(target_host, server_name, req).await?;
    let (status, status_text, response_headers) = extract_response_meta(&res);
    let incoming = res.into_body();

    if incoming.is_end_stream() {
        return Ok(JsStreamingResponse {
            attestation: attestation.into(),
            status,
            status_text,
            headers: response_headers,
            stream_id: 0,
        });
    }

    let stream_id = STREAM_ID.fetch_add(1, Ordering::SeqCst);
    STREAMS.lock().await.insert(
        stream_id,
        StreamState {
            incoming,
            pending: Bytes::new(),
            last_accessed: Instant::now(),
        },
    );

    // Spawn cleanup task periodically
    task::spawn(async {
        tokio::time::sleep(STREAM_IDLE_TIMEOUT).await;
        cleanup_idle_streams().await;
    });

    Ok(JsStreamingResponse {
        attestation: attestation.into(),
        status,
        status_text,
        headers: response_headers,
        stream_id,
    })
}

#[napi]
pub async fn stream_read(stream_id: u32, max_bytes: Option<u32>) -> napi::Result<Buffer> {
    let limit = max_bytes.unwrap_or(8192).max(1) as usize;
    let mut guard = STREAMS.lock().await;
    let Some(state) = guard.get_mut(&stream_id) else {
        return Ok(Buffer::from(Vec::new()));
    };

    // Update last accessed time to prevent idle cleanup
    state.last_accessed = Instant::now();

    if !state.pending.is_empty() {
        let take = state.pending.len().min(limit);
        let chunk = state.pending.split_to(take);
        return Ok(Buffer::from(chunk.to_vec()));
    }

    loop {
        match state.incoming.frame().await {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(mut data) => {
                    if data.is_empty() {
                        continue;
                    }
                    if data.len() > limit {
                        let chunk = data.split_to(limit);
                        state.pending = data;
                        return Ok(Buffer::from(chunk.to_vec()));
                    }
                    return Ok(Buffer::from(data.to_vec()));
                }
                Err(_frame) => continue, // Ignore non-data frames and keep reading.
            },
            Some(Err(e)) => return Err(Error::from_reason(format!("Stream error: {e}"))),
            None => {
                guard.remove(&stream_id);
                return Ok(Buffer::from(Vec::new()));
            }
        }
    }
}

#[napi]
pub async fn stream_close(stream_id: u32) -> napi::Result<()> {
    let mut guard = STREAMS.lock().await;
    guard.remove(&stream_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_prefixes_slash() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("foo"), "/foo");
        assert_eq!(normalize_path("/bar"), "/bar");
    }

    #[test]
    fn default_host_header_includes_non_default_port() {
        let host = default_host_header("example.com:8443", "example.com");
        assert_eq!(host, "example.com:8443");
    }

    #[test]
    fn default_host_header_omits_default_port() {
        let host = default_host_header("example.com:443", "example.com");
        assert_eq!(host, "example.com");
    }

    #[test]
    fn headers_to_map_sets_host_with_port_when_missing() {
        let host = default_host_header("example.com:8443", "example.com");
        let headers = headers_to_map(Vec::new(), &host).unwrap();
        assert_eq!(
            headers.get(HOST).and_then(|v| v.to_str().ok()),
            Some("example.com:8443")
        );
    }
}
