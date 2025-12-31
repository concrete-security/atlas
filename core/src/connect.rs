//! High-level RA-TLS connection API.
//!
//! This module provides the `ratls_connect` function that combines TLS handshake
//! with remote attestation verification in a single call.

use crate::error::RatlsVerificationError;
use crate::policy::Policy;
use crate::verifier::AsyncByteStream;
use crate::RatlsVerifier;
use dcap_qvl::verify::VerifiedReport;
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
) -> Result<(TlsStream<S>, Vec<u8>), RatlsVerificationError>
where
    S: AsyncByteStream + 'static,
{
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
        .map_err(|e| RatlsVerificationError::InvalidServerName(e.to_string()))?;

    let tls_stream = connector
        .connect(server_name_parsed, stream)
        .await
        .map_err(|e| RatlsVerificationError::TlsHandshake(e.to_string()))?;

    // Get peer certificate from the connection
    let (_, conn) = tls_stream.get_ref();
    let peer_cert = conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.as_ref().to_vec())
        .ok_or(RatlsVerificationError::MissingCertificate)?;

    Ok((tls_stream, peer_cert))
}

/// Establish a TLS connection with remote attestation verification.
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
/// A tuple of (TlsStream, VerifiedReport) on success.
///
/// # Example
///
/// ```no_run
/// use ratls_core::{ratls_connect, Policy, DstackTdxPolicy};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let tcp = tokio::net::TcpStream::connect("tee.example.com:443").await?;
/// let policy = Policy::DstackTdx(DstackTdxPolicy::dev());
/// let (tls_stream, report) = ratls_connect(tcp, "tee.example.com", policy, None).await?;
/// println!("TCB Status: {}", report.status);
/// # Ok(())
/// # }
/// ```
pub async fn ratls_connect<S>(
    stream: S,
    server_name: &str,
    policy: Policy,
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<S>, VerifiedReport), RatlsVerificationError>
where
    S: AsyncByteStream + 'static,
{
    let (mut tls_stream, peer_cert) = tls_handshake(stream, server_name, alpn).await?;

    let report = match policy {
        Policy::DstackTdx(tdx_policy) => {
            let verifier = tdx_policy.into_verifier()?;
            verifier
                .verify(&mut tls_stream, &peer_cert, server_name)
                .await?
        }
    };

    Ok((tls_stream, report))
}
