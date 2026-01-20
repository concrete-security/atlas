//! Minimal WebSocket -> TCP forwarder for aTLS tunnel testing.
//! Accepts binary WebSocket connections and pipes bytes to a configured TCP target.

use futures_util::{SinkExt, StreamExt};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message;
use url::form_urlencoded;

fn parse_allowlist(env_var: &str) -> HashSet<String> {
    std::env::var(env_var)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn is_target_allowed(target: &str, allowlist: &HashSet<String>) -> bool {
    allowlist.contains(target)
}

async fn handle_ws(
    ws_stream: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    target: String,
    allowlist: Arc<HashSet<String>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_target_allowed(&target, &allowlist) {
        eprintln!("Proxy: target {} is not in allowlist", target);
        return Err(format!("Target {} is not authorized", target).into());
    }
    let ws = ws_stream;
    println!("Proxy: connecting to target {}", target);
    let tcp = match TcpStream::connect(target.as_str()).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("Proxy: failed to connect to target {}: {}", target, e);
            return Err(Box::new(e));
        }
    };
    println!("Proxy: connected to target {}", target);

    let (mut ws_sink, mut ws_source) = ws.split();
    let (mut tcp_reader, mut tcp_writer) = tcp.into_split();
    let mut buf = [0u8; 8192];
    eprintln!("Established connection to target: {}", target);
    loop {
        tokio::select! {
            msg = ws_source.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        if msg.is_binary() || msg.is_text() {
                            tcp_writer.write_all(&msg.into_data()).await?;
                        } else if msg.is_close() {
                            let _ = ws_sink.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Some(Err(e)) => return Err(Box::new(e)),
                    None => break,
                }
            }
            res = tcp_reader.read(&mut buf) => {
                match res {
                    Ok(0) => {
                        let _ = ws_sink.send(Message::Close(None)).await;
                        break;
                    }
                    Ok(n) => {
                        ws_sink.send(Message::Binary(buf[..n].to_vec())).await?;
                    }
                    Err(e) => return Err(Box::new(e)),
                }
            }
        }
    }
    let _ = ws_sink.close().await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_addr =
        std::env::var("ATLS_PROXY_LISTEN").unwrap_or_else(|_| "127.0.0.1:9000".to_string());
    let target =
        std::env::var("ATLS_PROXY_TARGET").unwrap_or_else(|_| "127.0.0.1:8443".to_string());

    let allowlist = Arc::new(parse_allowlist("ATLS_PROXY_ALLOWLIST"));
    if allowlist.is_empty() {
        eprintln!(
            "WARNING: ATLS_PROXY_ALLOWLIST is empty or not set. All targets will be rejected."
        );
    } else {
        eprintln!(
            "Allowlist contains {} authorized target(s)",
            allowlist.len()
        );
    }

    if !is_target_allowed(&target, &allowlist) {
        eprintln!("ERROR: Default target {} is not in allowlist", target);
        return Err(format!("Default target {} is not authorized", target).into());
    }

    let listener = TcpListener::bind(&listen_addr).await?;
    eprintln!("atls-proxy listening on {listen_addr}, default target {target}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let default_target = target.clone();
        let allowlist_clone = allowlist.clone();
        tokio::spawn(async move {
            let shared_target = Arc::new(Mutex::new(default_target.clone()));
            let capture = shared_target.clone();
            let mut ws_stream =
                match accept_hdr_async(stream, move |req: &Request, response: Response| {
                    if let Some(tgt) = extract_target(req) {
                        eprintln!("Connection from {} requested target: {}", peer, tgt);
                        if let Ok(mut guard) = capture.lock() {
                            *guard = tgt;
                        }
                    } else {
                        eprintln!("Connection from {} using default target", peer);
                    }
                    Ok(response)
                })
                .await
                {
                    Ok(ws) => ws,
                    Err(e) => {
                        eprintln!("handshake error from {peer}: {e}");
                        return;
                    }
                };

            let final_target = shared_target
                .lock()
                .map(|guard| guard.clone())
                .unwrap_or(default_target);

            if !is_target_allowed(&final_target, &allowlist_clone) {
                eprintln!(
                    "Connection from {} rejected: target {} is not authorized",
                    peer, final_target
                );
                let _ = ws_stream.close(None).await;
                return;
            }

            if let Err(e) = handle_ws(ws_stream, final_target.clone(), allowlist_clone).await {
                eprintln!(
                    "pipe error for target {} from {}: {}",
                    final_target, peer, e
                );
            }
        });
    }
}

fn extract_target(req: &Request) -> Option<String> {
    req.uri().query().and_then(|query| {
        form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == "target")
            .map(|(_, value)| value.into_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Uri;

    #[test]
    fn test_parse_allowlist_empty() {
        // Temporarily clear the env var
        std::env::remove_var("TEST_ALLOWLIST_EMPTY");
        let result = parse_allowlist("TEST_ALLOWLIST_EMPTY");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_allowlist_single() {
        std::env::set_var("TEST_ALLOWLIST_SINGLE", "host1:443");
        let result = parse_allowlist("TEST_ALLOWLIST_SINGLE");
        assert_eq!(result.len(), 1);
        assert!(result.contains("host1:443"));
    }

    #[test]
    fn test_parse_allowlist_multiple() {
        std::env::set_var("TEST_ALLOWLIST_MULTI", "host1:443,host2:8443,host3:9000");
        let result = parse_allowlist("TEST_ALLOWLIST_MULTI");
        assert_eq!(result.len(), 3);
        assert!(result.contains("host1:443"));
        assert!(result.contains("host2:8443"));
        assert!(result.contains("host3:9000"));
    }

    #[test]
    fn test_parse_allowlist_with_whitespace() {
        std::env::set_var("TEST_ALLOWLIST_WS", "  host1:443  ,  host2:8443  ");
        let result = parse_allowlist("TEST_ALLOWLIST_WS");
        assert_eq!(result.len(), 2);
        assert!(result.contains("host1:443"));
        assert!(result.contains("host2:8443"));
    }

    #[test]
    fn test_parse_allowlist_with_empty_entries() {
        std::env::set_var("TEST_ALLOWLIST_EMPTY_ENTRIES", "host1:443,,host2:8443,");
        let result = parse_allowlist("TEST_ALLOWLIST_EMPTY_ENTRIES");
        assert_eq!(result.len(), 2);
        assert!(result.contains("host1:443"));
        assert!(result.contains("host2:8443"));
    }

    #[test]
    fn test_is_target_allowed_in_list() {
        let mut allowlist = HashSet::new();
        allowlist.insert("host1:443".to_string());
        allowlist.insert("host2:8443".to_string());

        assert!(is_target_allowed("host1:443", &allowlist));
        assert!(is_target_allowed("host2:8443", &allowlist));
    }

    #[test]
    fn test_is_target_allowed_not_in_list() {
        let mut allowlist = HashSet::new();
        allowlist.insert("host1:443".to_string());

        assert!(!is_target_allowed("host2:443", &allowlist));
        assert!(!is_target_allowed("host1:8443", &allowlist));
        assert!(!is_target_allowed("malicious.com:443", &allowlist));
    }

    #[test]
    fn test_is_target_allowed_empty_list() {
        let allowlist = HashSet::new();
        assert!(!is_target_allowed("any:443", &allowlist));
    }

    #[test]
    fn test_extract_target_with_target_param() {
        let uri: Uri = "/tunnel?target=host1:443".parse().unwrap();
        let req = Request::builder().uri(uri).body(()).unwrap();
        let result = extract_target(&req);
        assert_eq!(result, Some("host1:443".to_string()));
    }

    #[test]
    fn test_extract_target_with_multiple_params() {
        let uri: Uri = "/tunnel?foo=bar&target=host2:8443&baz=qux".parse().unwrap();
        let req = Request::builder().uri(uri).body(()).unwrap();
        let result = extract_target(&req);
        assert_eq!(result, Some("host2:8443".to_string()));
    }

    #[test]
    fn test_extract_target_no_query() {
        let uri: Uri = "/tunnel".parse().unwrap();
        let req = Request::builder().uri(uri).body(()).unwrap();
        let result = extract_target(&req);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_target_no_target_param() {
        let uri: Uri = "/tunnel?foo=bar&baz=qux".parse().unwrap();
        let req = Request::builder().uri(uri).body(()).unwrap();
        let result = extract_target(&req);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_target_url_encoded() {
        let uri: Uri = "/tunnel?target=host%3A443".parse().unwrap();
        let req = Request::builder().uri(uri).body(()).unwrap();
        let result = extract_target(&req);
        // URL decoding should handle %3A -> :
        assert_eq!(result, Some("host:443".to_string()));
    }
}
