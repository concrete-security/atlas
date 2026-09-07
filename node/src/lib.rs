use atlas_rs::{
    atls_connect_with_reattester as core_atls_connect_with_reattester,
    dstack::merge_with_default_app_compose, Policy, Reattester, Report, TlsStream as CoreTlsStream,
};
use bytes::{Bytes, BytesMut};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use once_cell::sync::Lazy;
use rustls::crypto::aws_lc_rs::default_provider;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::Mutex;

// Initialize the crypto provider once at module load
static CRYPTO_INIT: Lazy<()> = Lazy::new(|| {
    let _ = default_provider().install_default();
});

#[napi(object)]
pub struct JsAttestation {
    pub trusted: bool,
    #[napi(js_name = "teeType")]
    pub tee_type: String,
    pub measurement: Option<String>,
    #[napi(js_name = "tcbStatus")]
    pub tcb_status: String,
    #[napi(js_name = "advisoryIds")]
    pub advisory_ids: Vec<String>,
}

impl From<Report> for JsAttestation {
    fn from(report: Report) -> Self {
        match report {
            Report::Tdx(verified) => Self {
                trusted: true, // Success implies trusted
                tee_type: "tdx".to_string(),
                measurement: None, // VerifiedReport doesn't expose this directly
                tcb_status: verified.status.clone(),
                advisory_ids: verified.advisory_ids.clone(),
            },
        }
    }
}

#[napi(object)]
pub struct JsAtlsConnection {
    #[napi(js_name = "socketId")]
    pub socket_id: u32,
    pub attestation: JsAttestation,
    /// Max age (seconds) of attestation evidence before transparent
    /// re-attestation, from the policy. 0 means re-attestation is disabled.
    #[napi(js_name = "reattestationIntervalSecs")]
    pub reattestation_interval_secs: u32,
}

type TlsStream = CoreTlsStream<TcpStream>;

struct SocketState {
    reader: Arc<Mutex<ReadHalf<TlsStream>>>,
    writer: Arc<Mutex<WriteHalf<TlsStream>>>,
    reattester: Arc<Reattester>,
}

/// Upper bound on one in-band re-attestation exchange (quote generation,
/// possible collateral fetch, and DCAP verification included).
const REATTEST_TIMEOUT_SECS: u64 = 30;

static SOCKETS: Lazy<Mutex<HashMap<u32, SocketState>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static NEXT_SOCKET_ID: AtomicU32 = AtomicU32::new(1);

/// Merge a user-provided app_compose with default values.
///
/// This allows users to provide only the fields they care about (typically
/// `docker_compose_file` and `allowed_envs`) and get a complete app_compose
/// configuration with all required default fields filled in.
#[napi(js_name = "mergeWithDefaultAppCompose")]
pub fn merge_with_default_app_compose_js(user_compose: Value) -> Value {
    merge_with_default_app_compose(&user_compose)
}

/// Establish an aTLS connection and return a socket handle with attestation result.
#[napi(js_name = "atlsConnect")]
pub async fn atls_connect(
    target_host: String,
    server_name: String,
    policy_json: Value,
) -> napi::Result<JsAtlsConnection> {
    // Ensure crypto provider is initialized
    Lazy::force(&CRYPTO_INIT);

    // Parse and validate the policy from JSON
    let policy: Policy = serde_json::from_value(policy_json)
        .map_err(|e| Error::from_reason(format!("invalid policy: {e}")))?;

    let tcp_addr = lookup_host(&target_host)
        .await
        .map_err(|err| Error::from_reason(format!("invalid target host: {err}")))?
        .next()
        .ok_or_else(|| Error::from_reason("unable to resolve target host"))?;

    let tcp = TcpStream::connect(tcp_addr)
        .await
        .map_err(|err| Error::from_reason(format!("tcp connect failed: {err}")))?;

    let (tls, report, reattester) =
        core_atls_connect_with_reattester(tcp, &server_name, policy, Some(vec!["http/1.1".into()]))
            .await
            .map_err(|err| Error::from_reason(format!("atls handshake failed: {err}")))?;

    let reattestation_interval_secs = reattester.interval_secs().min(u32::MAX as u64) as u32;
    let socket_id = NEXT_SOCKET_ID.fetch_add(1, Ordering::SeqCst);
    let (reader, writer) = tokio::io::split(tls);
    SOCKETS.lock().await.insert(
        socket_id,
        SocketState {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            reattester: Arc::new(reattester),
        },
    );

    Ok(JsAtlsConnection {
        socket_id,
        attestation: report.into(),
        reattestation_interval_secs,
    })
}

/// Re-attest the connection in-band if its attestation evidence is older
/// than the policy's `reattestation_interval_secs`.
///
/// Must only be called while the connection is quiescent (no request or
/// response in flight): the exchange sends a `POST /tdx_quote` on the live
/// TLS stream and reads its response, holding both socket-half locks for the
/// duration so concurrent reads/writes block instead of interleaving.
///
/// Returns the fresh attestation when re-attestation ran, or `null` when the
/// evidence was still fresh (or re-attestation is disabled). On failure the
/// socket is torn down (fail closed) and an error is thrown; reconnecting
/// performs a full fresh attestation.
#[napi(js_name = "socketReattestIfDue")]
pub async fn socket_reattest_if_due(socket_id: u32) -> napi::Result<Option<JsAttestation>> {
    let (reader, writer, reattester) = {
        let guard = SOCKETS.lock().await;
        let Some(state) = guard.get(&socket_id) else {
            return Err(Error::from_reason("socket not found"));
        };
        (
            state.reader.clone(),
            state.writer.clone(),
            state.reattester.clone(),
        )
    };

    // Fast path without touching the socket locks.
    if !reattester.is_due() {
        return Ok(None);
    }

    // Lock order: writer then reader. Only this function ever holds both.
    let mut writer_guard = writer.lock().await;
    let mut reader_guard = reader.lock().await;

    // Re-check under the locks: a concurrent caller may have already
    // re-attested while we waited.
    if !reattester.is_due() {
        return Ok(None);
    }

    let mut joined = tokio::io::join(&mut *reader_guard, &mut *writer_guard);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(REATTEST_TIMEOUT_SECS),
        reattester.reattest(&mut joined),
    )
    .await;

    match result {
        Ok(Ok(report)) => Ok(Some(report.into())),
        Ok(Err(e)) => {
            // Fail closed: tear the connection down.
            drop(reader_guard);
            let _ = writer_guard.shutdown().await;
            drop(writer_guard);
            SOCKETS.lock().await.remove(&socket_id);
            Err(Error::from_reason(format!("reattestation failed: {e}")))
        }
        Err(_elapsed) => {
            // The exchange was cut off mid-flight; the stream state is
            // undefined, so the connection cannot be reused.
            drop(reader_guard);
            let _ = writer_guard.shutdown().await;
            drop(writer_guard);
            SOCKETS.lock().await.remove(&socket_id);
            Err(Error::from_reason(format!(
                "reattestation failed: timed out after {REATTEST_TIMEOUT_SECS}s"
            )))
        }
    }
}

/// Read data from socket
#[napi(js_name = "socketRead")]
pub async fn socket_read(socket_id: u32, size: Option<u32>) -> napi::Result<Buffer> {
    let max_size = size.unwrap_or(16384).max(1) as usize;
    let reader = {
        let guard = SOCKETS.lock().await;
        let Some(state) = guard.get(&socket_id) else {
            return Ok(Buffer::from(Vec::new()));
        };
        state.reader.clone()
    };

    let mut buf = BytesMut::zeroed(max_size);
    let mut reader = reader.lock().await;
    match reader.read(&mut buf).await {
        Ok(0) => {
            // EOF - remove socket
            let mut guard = SOCKETS.lock().await;
            guard.remove(&socket_id);
            Ok(Buffer::from(Vec::new()))
        }
        Ok(n) => {
            buf.truncate(n);
            Ok(Buffer::from(buf.to_vec()))
        }
        Err(e) => Err(Error::from_reason(format!("socket read error: {e}"))),
    }
}

/// Write data to socket
#[napi(js_name = "socketWrite")]
pub async fn socket_write(socket_id: u32, data: Buffer) -> napi::Result<u32> {
    let writer = {
        let guard = SOCKETS.lock().await;
        let Some(state) = guard.get(&socket_id) else {
            return Err(Error::from_reason("socket not found"));
        };
        state.writer.clone()
    };

    let bytes = Bytes::from(data.to_vec());
    {
        let mut writer = writer.lock().await;
        writer
            .write_all(&bytes)
            .await
            .map_err(|e| Error::from_reason(format!("socket write error: {e}")))?;
        writer
            .flush()
            .await
            .map_err(|e| Error::from_reason(format!("socket flush error: {e}")))?;
    }

    Ok(bytes.len() as u32)
}

/// Gracefully close the socket (flush + shutdown)
#[napi(js_name = "socketClose")]
pub async fn socket_close(socket_id: u32) -> napi::Result<()> {
    let writer = {
        let mut guard = SOCKETS.lock().await;
        guard.remove(&socket_id).map(|state| state.writer)
    };

    if let Some(writer) = writer {
        let mut writer = writer.lock().await;
        let _ = writer.flush().await;
        let _ = writer.shutdown().await;
    }

    Ok(())
}

/// Immediately destroy the socket
#[napi(js_name = "socketDestroy")]
pub fn socket_destroy(socket_id: u32) -> napi::Result<()> {
    // Spawn a task to remove the socket since we can't await in a sync function
    tokio::spawn(async move {
        let mut guard = SOCKETS.lock().await;
        guard.remove(&socket_id);
    });
    Ok(())
}

/// Close all open sockets - call before process exit for graceful cleanup.
///
/// This closes all open TLS connections and releases resources held by the
/// native binding. Call this before process.exit() to ensure clean shutdown.
#[napi(js_name = "closeAllSockets")]
pub async fn close_all_sockets() -> napi::Result<()> {
    let mut guard = SOCKETS.lock().await;

    // Close all sockets gracefully
    for (_, state) in guard.drain() {
        let mut writer = state.writer.lock().await;
        let _ = writer.flush().await;
        let _ = writer.shutdown().await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_id_increments() {
        let id1 = NEXT_SOCKET_ID.fetch_add(1, Ordering::SeqCst);
        let id2 = NEXT_SOCKET_ID.fetch_add(1, Ordering::SeqCst);
        assert!(id2 > id1);
    }

    /// The re-attestation exchange recombines the locked split halves with
    /// `tokio::io::join`; prove that adapter reads and writes correctly.
    #[tokio::test]
    async fn join_over_locked_halves_roundtrips() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(client);
        let reader = Arc::new(Mutex::new(reader));
        let writer = Arc::new(Mutex::new(writer));

        // Same locking pattern as socket_reattest_if_due: writer then reader.
        let mut writer_guard = writer.lock().await;
        let mut reader_guard = reader.lock().await;
        let mut joined = tokio::io::join(&mut *reader_guard, &mut *writer_guard);

        joined.write_all(b"ping").await.unwrap();
        joined.flush().await.unwrap();
        let mut request = [0u8; 4];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");

        server.write_all(b"pong").await.unwrap();
        let mut response = [0u8; 4];
        joined.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
    }
}
