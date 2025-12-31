//! Error types for RATLS verification.

use thiserror::Error;

/// Errors that can occur during RATLS verification.
#[derive(Debug, Error)]
pub enum RatlsVerificationError {
    /// I/O error during communication.
    #[error("I/O error: {0}")]
    Io(String),

    /// Quote verification failed.
    #[error("quote verification failed: {0}")]
    Quote(String),

    /// Bootchain measurement mismatch.
    #[error("bootchain mismatch: {field} expected {expected}, got {actual}")]
    BootchainMismatch {
        field: String,
        expected: String,
        actual: String,
    },

    /// RTMR measurement mismatch.
    #[error("RTMR{index} mismatch: expected {expected}, got {actual}")]
    RtmrMismatch {
        index: u8,
        expected: String,
        actual: String,
    },

    /// Certificate not found in event log.
    #[error("certificate not in event log")]
    CertificateNotInEventLog,

    /// App compose hash mismatch.
    #[error("app compose hash mismatch: expected {expected}, got {actual}")]
    AppComposeHashMismatch { expected: String, actual: String },

    /// OS image hash mismatch.
    #[error("OS image hash mismatch: expected {expected}, got {actual:?}")]
    OsImageHashMismatch {
        expected: String,
        actual: Option<String>,
    },

    /// TCB status not in allowed list.
    #[error("TCB status {status} not allowed (allowed: {allowed:?})")]
    TcbStatusNotAllowed { status: String, allowed: Vec<String> },

    /// Configuration error.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// TLS handshake failed.
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),

    /// Invalid server name.
    #[error("invalid server name: {0}")]
    InvalidServerName(String),

    /// Missing server certificate after TLS handshake.
    #[error("missing server certificate")]
    MissingCertificate,

    /// Other errors.
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
