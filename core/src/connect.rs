//! High-level aTLS connection API.
//!
//! This module provides the `atls_connect` function that combines TLS handshake
//! with attestation verification in a single call.

use log::debug;

use crate::error::AtlsVerificationError;
use crate::policy::Policy;
use crate::verifier::{AsyncByteStream, Report};
use crate::AtlsVerifier;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

// Platform-specific TLS types
#[cfg(not(target_arch = "wasm32"))]
pub use tokio_rustls::client::TlsStream;
#[cfg(not(target_arch = "wasm32"))]
use tokio_rustls::TlsConnector;

#[cfg(target_arch = "wasm32")]
pub use futures_rustls::client::TlsStream;
#[cfg(target_arch = "wasm32")]
use futures_rustls::TlsConnector;

/// Perform TLS handshake and return stream with peer certificate.
///
/// This establishes a TLS connection using CA-verified certificates from
/// the webpki-roots bundle and captures the server's leaf certificate.
///
/// # Arguments
///
/// * `stream` - The underlying transport stream (e.g., TcpStream)
/// * `server_name` - The server hostname for TLS SNI
/// * `alpn` - Optional ALPN protocols (e.g., `["http/1.1", "h2"]`)
///
/// # Returns
///
/// A tuple of (TlsStream, peer_certificate_der) on success.
pub async fn tls_handshake<S>(
    stream: S,
    server_name: &str,
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<S>, Vec<u8>), AtlsVerificationError>
where
    S: AsyncByteStream + 'static,
{
    debug!("Starting TLS handshake to {}", server_name);

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if let Some(protocols) = alpn {
        config.alpn_protocols = protocols.into_iter().map(|s| s.into_bytes()).collect();
    }

    let connector = TlsConnector::from(Arc::new(config));
    let server_name_parsed = ServerName::try_from(server_name.to_owned())
        .map_err(|e| AtlsVerificationError::InvalidServerName(e.to_string()))?;

    let tls_stream = connector
        .connect(server_name_parsed, stream)
        .await
        .map_err(|e| AtlsVerificationError::TlsHandshake(e.to_string()))?;

    // Get peer certificate from the connection
    let (_, conn) = tls_stream.get_ref();
    let peer_cert = conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.as_ref().to_vec())
        .ok_or(AtlsVerificationError::MissingCertificate)?;

    debug!(
        "TLS handshake complete, certificate received ({} bytes)",
        peer_cert.len()
    );

    Ok((tls_stream, peer_cert))
}

/// Establish a TLS connection with attestation verification.
///
/// This function combines TLS handshake with attestation verification:
/// 1. Performs a TLS handshake with CA certificate verification
/// 2. Captures the server's leaf certificate
/// 3. Creates the appropriate verifier from the policy
/// 4. Performs attestation verification over the TLS stream
/// 5. Returns the verified TLS stream and attestation report
///
/// # Arguments
///
/// * `stream` - The underlying transport stream (e.g., TcpStream)
/// * `server_name` - The server hostname for TLS SNI and verification
/// * `policy` - The attestation policy determining verifier and config
/// * `alpn` - Optional ALPN protocols (e.g., `["http/1.1", "h2"]`)
///
/// # Returns
///
/// A tuple of (TlsStream, Report) on success.
///
/// # Example
///
/// ```no_run
/// use atls_core::{atls_connect, Policy, DstackTdxPolicy};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let tcp = tokio::net::TcpStream::connect("tee.example.com:443").await?;
/// let policy = Policy::DstackTdx(DstackTdxPolicy::dev());
/// let (tls_stream, report) = atls_connect(tcp, "tee.example.com", policy, None).await?;
/// match &report {
///     atls_core::Report::Tdx(tdx_report) => {
///         println!("TCB Status: {}", tdx_report.status);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub async fn atls_connect<S>(
    stream: S,
    server_name: &str,
    policy: Policy,
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<S>, Report), AtlsVerificationError>
where
    S: AsyncByteStream + 'static,
{
    // Initialize logging (idempotent, only runs once)
    crate::logging::init();

    let (mut tls_stream, peer_cert) = tls_handshake(stream, server_name, alpn).await?;

    debug!("Starting attestation verification");
    let verifier = policy.into_verifier()?;
    let report = verifier
        .verify(&mut tls_stream, &peer_cert, server_name)
        .await?;

    debug!("Attestation verification successful");

    Ok((tls_stream, report))
}
