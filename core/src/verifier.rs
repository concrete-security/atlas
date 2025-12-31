//! RATLS verifier trait definition.

use std::future::Future;

use crate::error::RatlsVerificationError;

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

/// Trait for async RATLS verifiers.
///
/// This trait defines the interface for verifying remote attestation over TLS.
/// All methods are async to support both native (tokio) and WASM platforms.
///
/// Implementors provide TEE-specific verification logic, such as TDX quote
/// verification, bootchain validation, and certificate binding.
///
/// The associated `Report` type allows each TEE implementation to return its
/// own strongly-typed verification report (e.g., `VerifiedReport` for TDX).
///
/// On native platforms, the trait requires `Send + Sync` and futures must be `Send`.
/// On wasm32, these bounds are relaxed since wasm is single-threaded.
#[cfg(not(target_arch = "wasm32"))]
pub trait RatlsVerifier: Send + Sync {
    /// TEE-specific report type returned on successful verification.
    type Report;

    /// Verify the remote TEE via the given TLS connection.
    fn verify<S>(
        &self,
        stream: &mut S,
        peer_cert: &[u8],
        hostname: &str,
    ) -> impl Future<Output = Result<Self::Report, RatlsVerificationError>> + Send
    where
        S: AsyncByteStream;
}

/// Trait for async RATLS verifiers (wasm32 version, no Send required).
#[cfg(target_arch = "wasm32")]
pub trait RatlsVerifier: Sync {
    /// TEE-specific report type returned on successful verification.
    type Report;

    /// Verify the remote TEE via the given TLS connection.
    fn verify<S>(
        &self,
        stream: &mut S,
        peer_cert: &[u8],
        hostname: &str,
    ) -> impl Future<Output = Result<Self::Report, RatlsVerificationError>>
    where
        S: AsyncByteStream;
}
