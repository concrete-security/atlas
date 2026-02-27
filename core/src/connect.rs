//! High-level aTLS connection API.
//!
//! This module provides the `atls_connect` function that combines TLS handshake
//! with attestation verification in a single call.

use log::debug;

use crate::error::AtlsVerificationError;
use crate::policy::Policy;
use crate::verifier::{AsyncByteStream, Report};
use crate::AtlsVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
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

/// Custom certificate verifier that skips CA chain validation but preserves
/// TLS signature verification.
///
/// TEEs generate self-signed certificates, so CA chain validation would always
/// fail. Trust in aTLS comes from attestation (DCAP quote + certificate binding
/// via event log + EKM session binding), not from the CA hierarchy.
///
/// TLS signature verification is still performed to ensure the server holds
/// the private key corresponding to the certificate.
#[derive(Debug)]
struct AtlsServerCertVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl AtlsServerCertVerifier {
    fn new() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let supported_algs =
            rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
        #[cfg(target_arch = "wasm32")]
        let supported_algs =
            rustls::crypto::ring::default_provider().signature_verification_algorithms;
        Self { supported_algs }
    }
}

impl ServerCertVerifier for AtlsServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Skip CA chain validation — trust comes from attestation, not CA hierarchy.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // Delegate to crypto provider — server must prove it holds the private key.
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // Delegate to crypto provider — server must prove it holds the private key.
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Perform TLS handshake and return stream with peer certificate and session EKM.
///
/// This establishes a TLS connection and captures the server's leaf certificate
/// and TLS session Exported Keying Material (EKM) for session binding.
///
/// # Arguments
///
/// * `stream` - The underlying transport stream (e.g., TcpStream)
/// * `server_name` - The server hostname for TLS SNI
/// * `alpn` - Optional ALPN protocols (e.g., `["http/1.1", "h2"]`)
/// * `accept_self_signed_certs` - When `true`, skip CA chain validation (for TEE
///   self-signed certs). TLS signature verification is still performed.
///
/// # Returns
///
/// A tuple of (TlsStream, peer_certificate_der, session_ekm) on success.
pub async fn tls_handshake<S>(
    stream: S,
    server_name: &str,
    alpn: Option<Vec<String>>,
    accept_self_signed_certs: bool,
) -> Result<(TlsStream<S>, Vec<u8>, Vec<u8>), AtlsVerificationError>
where
    S: AsyncByteStream + 'static,
{
    debug!(
        "Starting TLS handshake to {} (accept_self_signed_certs={})",
        server_name, accept_self_signed_certs
    );

    let mut config = if accept_self_signed_certs {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AtlsServerCertVerifier::new()))
            .with_no_client_auth()
    } else {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

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
/// 1. Performs a TLS handshake (optionally accepting self-signed certificates)
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
    // Initialize logging (idempotent, only runs once)
    crate::logging::init();

    let accept_self_signed = policy.accept_self_signed_certs();
    let (mut tls_stream, peer_cert, session_ekm) =
        tls_handshake(stream, server_name, alpn, accept_self_signed).await?;

    debug!("Starting attestation verification");
    let verifier = policy.into_verifier()?;
    let report = verifier
        .verify(&mut tls_stream, &peer_cert, &session_ekm, server_name)
        .await?;

    debug!("Attestation verification successful");

    Ok((tls_stream, report))
}
