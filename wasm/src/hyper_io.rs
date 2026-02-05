//! IO adapter for hyper over futures::io streams.
//!
//! Hyper 1.x uses its own `hyper::rt::{Read, Write}` traits instead of tokio's.
//! This module provides a wrapper that adapts `futures::io::{AsyncRead, AsyncWrite}`
//! (used by atlas-rs on WASM) to hyper's traits.

use futures::io::{AsyncRead, AsyncWrite};
use hyper::rt::{Read, Write};
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

pin_project! {
    /// Wrapper that adapts `futures::io::{AsyncRead, AsyncWrite}` to `hyper::rt::{Read, Write}`.
    ///
    /// This allows using attested TLS streams with hyper's HTTP client.
    pub struct HyperIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> HyperIo<T> {
    /// Wrap a futures IO stream for use with hyper.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: AsyncRead> Read for HyperIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        // SAFETY: hyper guarantees the buffer is valid for writing
        let slice = unsafe { buf.as_mut() };

        // Create a properly initialized buffer for futures::io::AsyncRead
        // We need to zero-initialize because futures::AsyncRead expects initialized memory
        let len = slice.len();
        for byte in slice.iter_mut() {
            byte.write(0);
        }

        // SAFETY: We just initialized the buffer
        let initialized = unsafe { std::slice::from_raw_parts_mut(slice.as_mut_ptr() as *mut u8, len) };

        match self.project().inner.poll_read(cx, initialized) {
            Poll::Ready(Ok(n)) => {
                // SAFETY: we just read n bytes into the buffer
                unsafe { buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncWrite> Write for HyperIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_close(cx)
    }
}
