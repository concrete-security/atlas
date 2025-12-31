//! RATLS Verifier Library
//!
//! This library provides verifier implementations for Remote Attestation TLS (RATLS).
//!
//! # Overview
//!
//! The library provides two ways to verify TEE attestation:
//!
//! 1. **High-level API**: Use [`ratls_connect`] to establish a TLS connection with
//!    attestation verification in a single call.
//!
//! 2. **Low-level API**: Use the [`RatlsVerifier`] trait directly for custom TLS handling.
//!
//! # Features
//!
//! - **TDX Attestation**: Full TDX quote verification using Intel DCAP
//! - **Bootchain Verification**: Verify MRTD and RTMR0-2 measurements
//! - **Event Log Replay**: Verify RTMR3 by replaying event logs
//! - **App Compose Verification**: Verify application configuration hash
//! - **OS Image Verification**: Verify the OS image hash
//! - **Certificate Binding**: Verify TLS certificate is bound to the TEE
//!
//! # High-Level Example
//!
//! ```no_run
//! use ratls_core::{ratls_connect, Policy, DstackTdxPolicy};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect with development policy (relaxed TCB status)
//! let tcp = tokio::net::TcpStream::connect("tee.example.com:443").await?;
//! let policy = Policy::DstackTdx(DstackTdxPolicy::dev());
//! let (tls_stream, report) = ratls_connect(tcp, "tee.example.com", policy, None).await?;
//!
//! println!("TCB Status: {}", report.status);
//! # Ok(())
//! # }
//! ```
//!
//! # Low-Level Example
//!
//! ```no_run
//! use ratls_core::{DstackTDXVerifier, ExpectedBootchain, RatlsVerifier};
//! use serde_json::json;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let verifier = DstackTDXVerifier::builder()
//!     .app_compose(json!({
//!         "runner": "docker-compose",
//!         "docker_compose_file": "..."
//!     }))
//!     .expected_bootchain(ExpectedBootchain {
//!         mrtd: "abc123...".to_string(),
//!         rtmr0: "def456...".to_string(),
//!         rtmr1: "ghi789...".to_string(),
//!         rtmr2: "jkl012...".to_string(),
//!     })
//!     .os_image_hash("86b181...")
//!     .build()
//!     .unwrap();
//!
//! // Use the verifier with a TLS stream (async)
//! # let mut tls_stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream> = todo!();
//! # let peer_cert: Vec<u8> = todo!();
//! let report = verifier.verify(&mut tls_stream, &peer_cert, "hostname").await?;
//! println!("TCB Status: {}", report.status);
//! # Ok(())
//! # }
//! ```

pub mod compose_hash;
pub mod connect;
pub mod error;
pub mod policy;
pub mod tdx;
pub mod verifier;

// High-level API
pub use connect::{ratls_connect, tls_handshake, TlsStream};
pub use policy::{DstackTdxPolicy, Policy};

// Low-level API
pub use error::RatlsVerificationError;
pub use tdx::{DstackTDXVerifier, DstackTDXVerifierBuilder, DstackTDXVerifierConfig, ExpectedBootchain};
pub use verifier::{AsyncByteStream, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, RatlsVerifier};

// Re-export VerifiedReport from dcap-qvl for bindings
pub use dcap_qvl::verify::VerifiedReport;
