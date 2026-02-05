//! aTLS Verifier Library
//!
//! This library provides verifier implementations for Attested TLS (aTLS).
//!
//! # Overview
//!
//! The library provides two ways to verify TEE attestation:
//!
//! 1. **High-level API**: Use [`atls_connect`] to establish a TLS connection with
//!    attestation verification in a single call.
//!
//! 2. **Low-level API**: Use the [`AtlsVerifier`] trait directly for custom TLS handling.
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
//! For architecture details and how to extend with new TEE verifiers, see
//! [ARCHITECTURE.md](https://github.com/anthropics/atls/blob/main/core/ARCHITECTURE.md).
//!
//! # High-Level Example
//!
//! ```no_run
//! use atlas_rs::{atls_connect, Policy, DstackTdxPolicy};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect with development policy (relaxed TCB status)
//! let tcp = tokio::net::TcpStream::connect("tee.example.com:443").await?;
//! let policy = Policy::DstackTdx(DstackTdxPolicy::dev());
//! let (tls_stream, report) = atls_connect(tcp, "tee.example.com", policy, None).await?;
//!
//! // Access report data via pattern matching
//! match &report {
//!     atlas_rs::Report::Tdx(tdx_report) => {
//!         println!("TCB Status: {}", tdx_report.status);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Low-Level Example
//!
//! ```no_run
//! use atlas_rs::{DstackTDXVerifier, AtlsVerifier};
//! use atlas_rs::tdx::ExpectedBootchain;
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
//! # let session_ekm: Vec<u8> = todo!();
//! let report = verifier.verify(&mut tls_stream, &peer_cert, &session_ekm, "hostname").await?;
//! match &report {
//!     atlas_rs::Report::Tdx(tdx_report) => {
//!         println!("TCB Status: {}", tdx_report.status);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

pub mod connect;
pub mod dstack;
pub mod error;
pub mod logging;
pub mod policy;
pub mod tdx;
pub mod verifier;

// High-level API
pub use connect::{atls_connect, TlsStream};
pub use policy::Policy;

// Dstack-specific (backward compatible re-exports)
// NOTE: compose_hash NOT exposed at root - access via dstack::compose_hash
pub use dstack::{DstackTDXVerifier, DstackTDXVerifierBuilder, DstackTDXVerifierConfig, DstackTdxPolicy};

// Generic TDX
pub use tdx::{ExpectedBootchain, TCB_STATUS_LIST};

// Low-level API
pub use error::AtlsVerificationError;
pub use verifier::{
    AsyncByteStream, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, IntoVerifier, AtlsVerifier,
    Report, Verifier,
};

// Re-export VerifiedReport from dcap-qvl for bindings
pub use dcap_qvl::verify::VerifiedReport;
