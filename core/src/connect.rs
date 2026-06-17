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
use rustls::client::WebPkiServerVerifier;
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
    tls_handshake_with_cert_name(stream, server_name, server_name, alpn).await
}

/// Perform TLS handshake with independent SNI routing and certificate identity.
///
/// `route_server_name` is sent as TLS SNI so an ingress gateway can route the
/// connection. `cert_server_name` is still used for normal WebPKI hostname
/// validation against the presented certificate.
///
/// Crate-internal: callers outside the crate should use the high-level
/// [`atls_connect_with_route_sni`].
pub(crate) async fn tls_handshake_with_cert_name<S>(
    stream: S,
    route_server_name: &str,
    cert_server_name: &str,
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<S>, Vec<u8>, Vec<u8>), AtlsVerificationError>
where
    S: AsyncByteStream + 'static,
{
    debug!(
        "Starting TLS handshake to {} with certificate identity {}",
        route_server_name, cert_server_name
    );

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let cert_name = ServerName::try_from(cert_server_name.to_owned())
        .map_err(|e| AtlsVerificationError::InvalidServerName(e.to_string()))?;
    let verifier = WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| {
            AtlsVerificationError::TlsHandshake(format!(
                "Failed to build certificate verifier: {}",
                e
            ))
        })?;
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CertificateNameVerifier {
            inner: verifier,
            cert_name,
        }))
        .with_no_client_auth();

    if let Some(protocols) = alpn {
        config.alpn_protocols = protocols.into_iter().map(|s| s.into_bytes()).collect();
    }

    let connector = TlsConnector::from(Arc::new(config));
    let server_name_parsed = ServerName::try_from(route_server_name.to_owned())
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

#[derive(Debug)]
struct CertificateNameVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    cert_name: ServerName<'static>,
}

impl ServerCertVerifier for CertificateNameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            &self.cert_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
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
    // Initialize logging (idempotent, only runs once)
    crate::logging::init();

    let (mut tls_stream, peer_cert, session_ekm) = tls_handshake(stream, server_name, alpn).await?;

    debug!("Starting attestation verification");
    let verifier = policy.into_verifier()?;
    let report = verifier
        .verify(&mut tls_stream, &peer_cert, &session_ekm, server_name)
        .await?;

    debug!("Attestation verification successful");

    Ok((tls_stream, report))
}

/// Establish a TLS connection with independent SNI routing and attestation verification.
///
/// `server_name` remains the certificate and attestation identity. `route_server_name`
/// is used only for the TLS SNI value required by some ingress gateways.
pub async fn atls_connect_with_route_sni<S>(
    stream: S,
    server_name: &str,
    route_server_name: &str,
    policy: Policy,
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<S>, Report), AtlsVerificationError>
where
    S: AsyncByteStream + 'static,
{
    crate::logging::init();

    let (mut tls_stream, peer_cert, session_ekm) =
        tls_handshake_with_cert_name(stream, route_server_name, server_name, alpn).await?;

    debug!("Starting attestation verification");
    let verifier = policy.into_verifier()?;
    let report = verifier
        .verify(&mut tls_stream, &peer_cert, &session_ekm, server_name)
        .await?;

    debug!("Attestation verification successful");

    Ok((tls_stream, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Inner verifier stub that records the `server_name` it is handed and
    /// otherwise approves everything, so a test can observe which identity the
    /// wrapping verifier forwarded.
    #[derive(Debug)]
    struct RecordingVerifier {
        seen_name: Mutex<Option<ServerName<'static>>>,
    }

    impl ServerCertVerifier for RecordingVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            *self.seen_name.lock().unwrap() = Some(server_name.to_owned());
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
    }

    /// Regression test for independent SNI routing: `CertificateNameVerifier`
    /// must verify the certificate against `cert_name` (the attestation/cert
    /// identity) and never leak the routed SNI to the inner verifier.
    #[test]
    fn certificate_name_verifier_uses_cert_name_not_routed_sni() {
        let recorder = Arc::new(RecordingVerifier {
            seen_name: Mutex::new(None),
        });
        let cert_name = ServerName::try_from("cert.example.com").unwrap();
        let routed_sni = ServerName::try_from("gateway.route.example").unwrap();

        let verifier = CertificateNameVerifier {
            inner: recorder.clone(),
            cert_name: cert_name.clone(),
        };

        let dummy_cert = CertificateDer::from(vec![0u8; 4]);
        let result = verifier.verify_server_cert(
            &dummy_cert,
            &[],
            &routed_sni,
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(0)),
        );
        assert!(result.is_ok());

        let seen = recorder.seen_name.lock().unwrap().clone();
        assert_eq!(
            seen,
            Some(cert_name),
            "inner verifier must receive cert_server_name"
        );
        assert_ne!(
            seen,
            Some(routed_sni),
            "routed SNI must never reach the inner verifier"
        );
    }
}
