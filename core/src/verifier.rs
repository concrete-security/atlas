//! aTLS verifier trait definition.

use std::future::Future;

use crate::error::AtlsVerificationError;
use dcap_qvl::verify::VerifiedReport;

// Platform-specific async I/O traits
#[cfg(not(target_arch = "wasm32"))]
pub use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(target_arch = "wasm32")]
pub use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Trait alias for async byte streams on native targets.
#[cfg(not(target_arch = "wasm32"))]
pub trait AsyncByteStream: AsyncRead + AsyncWrite + Unpin + Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncByteStream for T {}

/// Trait alias for async byte streams on wasm, where `Send` is not required.
#[cfg(target_arch = "wasm32")]
pub trait AsyncByteStream: AsyncRead + AsyncWrite + Unpin {}
#[cfg(target_arch = "wasm32")]
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncByteStream for T {}

/// Unified report type returned by all aTLS verifiers.
///
/// Each variant wraps a TEE-specific report type, preserving full type information.
/// Users can match on the variant to access TEE-specific details.
///
/// # Example
///
/// ```
/// use atls_core::Report;
///
/// fn handle_report(report: Report) {
///     match report {
///         Report::Tdx(tdx_report) => {
///             println!("TCB Status: {}", tdx_report.status);
///             println!("TDX Report: {:?}", tdx_report);
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub enum Report {
    /// TDX attestation report.
    Tdx(VerifiedReport),
}

impl Report {
    /// Try to get the underlying TDX report.
    ///
    /// Returns `Some(&VerifiedReport)` if this is a TDX report, `None` otherwise.
    pub fn as_tdx(&self) -> Option<&VerifiedReport> {
        match self {
            Report::Tdx(r) => Some(r),
        }
    }

    /// Consume self and try to get the underlying TDX report.
    ///
    /// Returns `Some(VerifiedReport)` if this is a TDX report, `None` otherwise.
    pub fn into_tdx(self) -> Option<VerifiedReport> {
        match self {
            Report::Tdx(r) => Some(r),
        }
    }
}

/// Trait for async aTLS verifiers.
///
/// This trait defines the interface for verifying attestation over TLS.
/// All methods are async to support both native (tokio) and WASM platforms.
///
/// Implementors provide TEE-specific verification logic, such as TDX quote
/// verification, bootchain validation, and certificate binding.
///
/// All verifiers return a unified [`Report`] type that wraps TEE-specific reports.
///
/// On native platforms, the trait requires `Send + Sync` and futures must be `Send`.
/// On wasm32, these bounds are relaxed since wasm is single-threaded.
#[cfg(not(target_arch = "wasm32"))]
pub trait AtlsVerifier: Send + Sync {
    /// Verify the remote TEE via the given TLS connection.
    fn verify<S>(
        &self,
        stream: &mut S,
        peer_cert: &[u8],
        hostname: &str,
    ) -> impl Future<Output = Result<Report, AtlsVerificationError>> + Send
    where
        S: AsyncByteStream;
}

/// Trait for async aTLS verifiers (wasm32 version, no Send required).
#[cfg(target_arch = "wasm32")]
pub trait AtlsVerifier: Sync {
    /// Verify the remote TEE via the given TLS connection.
    fn verify<S>(
        &self,
        stream: &mut S,
        peer_cert: &[u8],
        hostname: &str,
    ) -> impl Future<Output = Result<Report, AtlsVerificationError>>
    where
        S: AsyncByteStream;
}

/// Trait for types that can be converted into an [`AtlsVerifier`].
///
/// This trait is implemented by policy types (like [`DstackTdxPolicy`](crate::DstackTdxPolicy))
/// to convert configuration into a concrete verifier instance.
///
/// # Example
///
/// ```
/// use atls_core::{DstackTdxPolicy, IntoVerifier};
///
/// let policy = DstackTdxPolicy::dev();
/// let verifier = policy.into_verifier().unwrap();
/// ```
pub trait IntoVerifier {
    /// The verifier type produced by this conversion.
    type Verifier: AtlsVerifier;

    /// Convert this policy/config into a verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or incomplete.
    fn into_verifier(self) -> Result<Self::Verifier, AtlsVerificationError>;
}

/// Enum wrapping all concrete verifier implementations.
///
/// This enables [`Policy::into_verifier()`](crate::Policy::into_verifier) to return a single type
/// while supporting multiple TEE verifiers. Follows the same pattern as [`Report`].
///
/// # Example
///
/// ```
/// use atls_core::{Policy, DstackTdxPolicy, AtlsVerifier};
///
/// let policy = Policy::DstackTdx(DstackTdxPolicy::dev());
/// let verifier = policy.into_verifier().unwrap();
///
/// // The verifier can be used with any async stream
/// // verifier.verify(&mut stream, &peer_cert, hostname).await
/// ```
pub enum Verifier {
    /// DStack TDX verifier.
    DstackTdx(crate::dstack::DstackTDXVerifier),
}

#[cfg(not(target_arch = "wasm32"))]
impl AtlsVerifier for Verifier {
    fn verify<S>(
        &self,
        stream: &mut S,
        peer_cert: &[u8],
        hostname: &str,
    ) -> impl Future<Output = Result<Report, AtlsVerificationError>> + Send
    where
        S: AsyncByteStream,
    {
        async move {
            match self {
                Verifier::DstackTdx(v) => v.verify(stream, peer_cert, hostname).await,
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AtlsVerifier for Verifier {
    fn verify<S>(
        &self,
        stream: &mut S,
        peer_cert: &[u8],
        hostname: &str,
    ) -> impl Future<Output = Result<Report, AtlsVerificationError>>
    where
        S: AsyncByteStream,
    {
        async move {
            match self {
                Verifier::DstackTdx(v) => v.verify(stream, peer_cert, hostname).await,
            }
        }
    }
}
