//! High-level aTLS connection API.
//!
//! This module provides the `atls_connect` function that combines TLS handshake
//! with attestation verification in a single call.

use log::debug;

use crate::error::AtlsVerificationError;
use crate::policy::Policy;
use crate::reattest::Reattester;
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

/// Perform TLS handshake and return stream with peer certificate and session EKM.
///
/// This establishes a TLS connection using CA-verified certificates from
/// the webpki-roots bundle and captures the server's leaf certificate and
/// TLS session Exported Keying Material (EKM) for session binding.
///
/// # Arguments
///
/// * `stream` - The underlying transport stream (e.g., TcpStream)
/// * `server_name` - The server hostname for TLS SNI
/// * `alpn` - Optional ALPN protocols (e.g., `["http/1.1", "h2"]`)
///
/// # Returns
///
/// A tuple of (TlsStream, peer_certificate_der, session_ekm) on success.
pub async fn tls_handshake<S>(
    stream: S,
    server_name: &str,
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<S>, Vec<u8>, Vec<u8>), AtlsVerificationError>
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

    // Extract EKM for session binding (RFC 9266)
    let mut session_ekm = vec![0u8; 32];
    conn.export_keying_material(&mut session_ekm, b"EXPORTER-Channel-Binding", None)
        .map_err(|e| {
            AtlsVerificationError::TlsHandshake(format!("Failed to extract session EKM: {}", e))
        })?;

    debug!("Session EKM extracted ({} bytes)", session_ekm.len());

    Ok((tls_stream, peer_cert, session_ekm))
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
/// use atlas_rs::{atls_connect, Policy, DstackTdxPolicy};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let tcp = tokio::net::TcpStream::connect("tee.example.com:443").await?;
/// let policy = Policy::DstackTdx(DstackTdxPolicy::dev());
/// let (tls_stream, report) = atls_connect(tcp, "tee.example.com", policy, None).await?;
/// match &report {
///     atlas_rs::Report::Tdx(tdx_report) => {
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
    let (tls_stream, report, _reattester) =
        atls_connect_with_reattester(stream, server_name, policy, alpn).await?;
    Ok((tls_stream, report))
}

/// Establish a verified aTLS connection and return a re-attestation handle.
///
/// Identical to [`atls_connect`], but additionally returns a
/// [`Reattester`] retaining the verifier, session peer certificate, and
/// session EKM, so the connection can be transparently re-verified during
/// its lifetime. See [`crate::reattest`] for usage and safety requirements.
///
/// The re-attestation interval comes from the policy
/// (`reattestation_interval_secs`, default 300 seconds; 0 disables
/// re-attestation, in which case [`Reattester::is_due`] is always false).
///
/// # Example
///
/// ```no_run
/// use atlas_rs::{atls_connect_with_reattester, Policy, DstackTdxPolicy};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let tcp = tokio::net::TcpStream::connect("tee.example.com:443").await?;
/// let policy = Policy::DstackTdx(DstackTdxPolicy::dev());
/// let (mut tls_stream, report, reattester) =
///     atls_connect_with_reattester(tcp, "tee.example.com", policy, None).await?;
///
/// // ... use the connection ...
///
/// // Later, at a message boundary (no request/response in flight):
/// if reattester.is_due() {
///     let fresh_report = reattester.reattest(&mut tls_stream).await?;
/// }
/// # Ok(())
/// # }
/// ```
pub async fn atls_connect_with_reattester<S>(
    stream: S,
    server_name: &str,
    policy: Policy,
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<S>, Report, Reattester), AtlsVerificationError>
where
    S: AsyncByteStream + 'static,
{
    // Initialize logging (idempotent, only runs once)
    crate::logging::init();

    let (mut tls_stream, peer_cert, session_ekm) = tls_handshake(stream, server_name, alpn).await?;

    debug!("Starting attestation verification");
    let verifier = policy.into_verifier()?;
    // Anchor the evidence age at the moment verification starts (nonce
    // issuance), not when it completes, so a slow exchange cannot overstate
    // freshness.
    let verified_at_millis = crate::time::mono_millis();
    let report = verifier
        .verify(&mut tls_stream, &peer_cert, &session_ekm, server_name)
        .await?;

    debug!("Attestation verification successful");

    let reattester = Reattester::new_at(
        verifier,
        peer_cert,
        session_ekm,
        server_name.to_string(),
        verified_at_millis,
    );

    Ok((tls_stream, report, reattester))
}
