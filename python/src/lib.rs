use atlas_rs::{
    atls_connect as core_atls_connect, dstack::merge_with_default_app_compose, Policy, Report,
    TlsStream as CoreTlsStream,
};
use once_cell::sync::Lazy;
use pyo3::exceptions::{PyConnectionError, PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use rustls::crypto::aws_lc_rs::default_provider;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

// Lazily initialized tokio runtime shared across all connections.
static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
});

// Initialize the crypto provider once.
static CRYPTO_INIT: Lazy<()> = Lazy::new(|| {
    let _ = default_provider().install_default();
});

type TlsStream = CoreTlsStream<TcpStream>;

struct ConnectionState {
    reader: Arc<Mutex<ReadHalf<TlsStream>>>,
    writer: Arc<Mutex<WriteHalf<TlsStream>>>,
    attestation: Attestation,
}

static CONNECTIONS: Lazy<Mutex<HashMap<u64, ConnectionState>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct Attestation {
    trusted: bool,
    tee_type: String,
    measurement: Option<String>,
    tcb_status: String,
    advisory_ids: Vec<String>,
}

impl From<Report> for Attestation {
    fn from(report: Report) -> Self {
        match report {
            Report::Tdx(verified) => {
                let measurement = verified
                    .report
                    .as_td10()
                    .map(|td| hex::encode(td.mr_td));
                Self {
                    trusted: true,
                    tee_type: "tdx".to_string(),
                    measurement,
                    tcb_status: verified.status.clone(),
                    advisory_ids: verified.advisory_ids.clone(),
                }
            }
        }
    }
}

impl Attestation {
    fn to_py_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        dict.set_item("trusted", self.trusted)?;
        dict.set_item("tee_type", &self.tee_type)?;
        dict.set_item("measurement", &self.measurement)?;
        dict.set_item("tcb_status", &self.tcb_status)?;
        dict.set_item("advisory_ids", &self.advisory_ids)?;
        Ok(dict.into_any().unbind())
    }
}

/// An attested TLS connection backed by Rust.
///
/// Provides read/write access to an attested TLS stream and the attestation report.
/// The connection is created by `atls_connect()` and stays open for HTTP communication.
#[pyclass]
struct AtlsConnection {
    conn_id: u64,
}

impl Drop for AtlsConnection {
    fn drop(&mut self) {
        let conn_id = self.conn_id;
        let _ = RUNTIME.block_on(async { CONNECTIONS.lock().await.remove(&conn_id) });
    }
}

#[pymethods]
impl AtlsConnection {
    /// Read up to `size` bytes from the attested TLS stream.
    ///
    /// Blocks until data is available. Returns empty bytes on EOF.
    /// The GIL is released during the blocking read.
    fn read(&self, py: Python<'_>, size: usize) -> PyResult<Vec<u8>> {
        let conn_id = self.conn_id;
        py.allow_threads(|| {
            RUNTIME.block_on(async {
                let reader = {
                    let guard = CONNECTIONS.lock().await;
                    let state = guard
                        .get(&conn_id)
                        .ok_or_else(|| PyIOError::new_err("connection closed"))?;
                    state.reader.clone()
                };

                let mut buf = vec![0u8; size];
                let mut reader = reader.lock().await;
                match reader.read(&mut buf).await {
                    Ok(0) => Ok(Vec::new()),
                    Ok(n) => {
                        buf.truncate(n);
                        Ok(buf)
                    }
                    Err(e) => Err(PyIOError::new_err(format!("read error: {e}"))),
                }
            })
        })
    }

    /// Write data to the attested TLS stream.
    ///
    /// Returns the number of bytes written. The GIL is released during the write.
    fn write(&self, py: Python<'_>, data: Vec<u8>) -> PyResult<usize> {
        let conn_id = self.conn_id;
        let len = data.len();
        py.allow_threads(|| {
            RUNTIME.block_on(async {
                let writer = {
                    let guard = CONNECTIONS.lock().await;
                    let state = guard
                        .get(&conn_id)
                        .ok_or_else(|| PyIOError::new_err("connection closed"))?;
                    state.writer.clone()
                };

                let mut writer = writer.lock().await;
                writer
                    .write_all(&data)
                    .await
                    .map_err(|e| PyIOError::new_err(format!("write error: {e}")))?;
                writer
                    .flush()
                    .await
                    .map_err(|e| PyIOError::new_err(format!("flush error: {e}")))?;

                Ok(len)
            })
        })
    }

    /// Close the connection gracefully.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let conn_id = self.conn_id;
        py.allow_threads(|| {
            RUNTIME.block_on(async {
                let writer = {
                    let mut guard = CONNECTIONS.lock().await;
                    guard.remove(&conn_id).map(|state| state.writer)
                };

                if let Some(writer) = writer {
                    let mut writer = writer.lock().await;
                    let _ = writer.flush().await;
                    let _ = writer.shutdown().await;
                }

                Ok(())
            })
        })
    }

    /// Get the attestation report as a dict.
    ///
    /// Returns: {"trusted": bool, "tee_type": str, "measurement": str | None, "tcb_status": str, "advisory_ids": list[str]}
    #[getter]
    fn attestation(&self, py: Python<'_>) -> PyResult<PyObject> {
        let conn_id = self.conn_id;
        let attestation = RUNTIME.block_on(async {
            let guard = CONNECTIONS.lock().await;
            let state = guard
                .get(&conn_id)
                .ok_or_else(|| PyIOError::new_err("connection closed"))?;
            Ok::<_, PyErr>(state.attestation.clone())
        })?;

        attestation.to_py_dict(py)
    }
}

/// Establish an attested TLS connection to a TEE endpoint.
///
/// Creates a TCP connection, performs TLS handshake, and runs attestation
/// verification. Returns an AtlsConnection with read/write access to the
/// attested stream.
///
/// Args:
///     host: Target hostname or IP.
///     port: Target port.
///     server_name: TLS SNI server name (usually same as host).
///     policy_json: JSON string of the attestation policy.
///
/// Returns:
///     AtlsConnection with .read()/.write()/.close()/.attestation
///
/// Raises:
///     ValueError: If the policy JSON is invalid.
///     ConnectionError: If TCP connection or TLS handshake fails.
///     IOError: If attestation verification fails.
#[pyfunction]
fn atls_connect(
    py: Python<'_>,
    host: &str,
    port: u16,
    server_name: &str,
    policy_json: &str,
) -> PyResult<AtlsConnection> {
    // Ensure crypto provider is initialized
    Lazy::force(&CRYPTO_INIT);

    let policy: Policy = serde_json::from_str(policy_json)
        .map_err(|e| PyValueError::new_err(format!("invalid policy JSON: {e}")))?;

    let target = format!("{host}:{port}");
    let server_name = server_name.to_string();

    py.allow_threads(|| {
        RUNTIME.block_on(async {
            let tcp = TcpStream::connect(&target)
                .await
                .map_err(|e| PyConnectionError::new_err(format!("tcp connect failed: {e}")))?;

            let (tls, report) =
                core_atls_connect(tcp, &server_name, policy, Some(vec!["http/1.1".into()]))
                    .await
                    .map_err(|e| PyIOError::new_err(format!("atls handshake failed: {e}")))?;

            let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::SeqCst);
            let (reader, writer) = tokio::io::split(tls);

            let attestation: Attestation = report.into();

            CONNECTIONS.lock().await.insert(
                conn_id,
                ConnectionState {
                    reader: Arc::new(Mutex::new(reader)),
                    writer: Arc::new(Mutex::new(writer)),
                    attestation,
                },
            );

            Ok(AtlsConnection { conn_id })
        })
    })
}

/// Merge a user-provided app_compose JSON with default values.
///
/// Args:
///     user_compose_json: JSON string of user-provided fields.
///
/// Returns:
///     JSON string of the merged app_compose with all defaults filled in.
#[pyfunction]
fn merge_with_default_app_compose_py(user_compose_json: &str) -> PyResult<String> {
    let value: serde_json::Value = serde_json::from_str(user_compose_json)
        .map_err(|e| PyValueError::new_err(format!("invalid JSON: {e}")))?;

    let merged = merge_with_default_app_compose(&value);

    serde_json::to_string(&merged)
        .map_err(|e| PyValueError::new_err(format!("serialization error: {e}")))
}

/// Atlas Python bindings for attested TLS (aTLS).
#[pymodule]
fn _atlas(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AtlsConnection>()?;
    m.add_function(wrap_pyfunction!(atls_connect, m)?)?;
    m.add_function(wrap_pyfunction!(merge_with_default_app_compose_py, m)?)?;
    Ok(())
}
