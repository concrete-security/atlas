//! WASM bindings for aTLS connections.
//!
//! This module provides a minimal API for establishing attested TLS connections
//! from browsers. It exposes native Web Streams (ReadableStream) for response reading.
//!
//! The HTTP client uses `hyper` for security - preventing CRLF injection attacks
//! and properly handling chunked transfer encoding.

#![cfg(target_arch = "wasm32")]

mod hyper_io;

use async_io_stream::IoStream;
use atlas_rs::{
    atls_connect, atls_connect_with_reattester, dstack::merge_with_default_app_compose,
    AsyncWriteExt, Policy, ReattestRequest, Reattester, Report, TlsStream,
};
use bytes::Bytes;
use futures::io::{ReadHalf, WriteHalf};
use futures::AsyncReadExt;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::Request;
use serde::Serialize;
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;
use web_sys::js_sys::{Object, Promise, Reflect, Uint8Array};
use web_sys::ReadableStreamDefaultController;
use ws_stream_wasm::{WsMeta, WsStreamIo};

use hyper_io::HyperIo;

// ============================================================================
// App Compose Utilities
// ============================================================================

/// Merge user-provided app_compose with default values.
///
/// This allows users to provide only the fields they care about
/// (typically docker_compose_file and allowed_envs) and get a complete
/// app_compose configuration with all required default fields filled in.
///
/// User-provided values override defaults.
#[wasm_bindgen(js_name = mergeWithDefaultAppCompose)]
pub fn merge_with_default_app_compose_js(user_compose: JsValue) -> Result<JsValue, JsValue> {
    let user_value: serde_json::Value = serde_wasm_bindgen::from_value(user_compose)
        .map_err(|e| JsValue::from_str(&format!("invalid app_compose: {e}")))?;

    let merged = merge_with_default_app_compose(&user_value);

    serde_wasm_bindgen::to_value(&merged)
        .map_err(|e| JsValue::from_str(&format!("failed to serialize merged app_compose: {e}")))
}

type WsIo = IoStream<WsStreamIo, Vec<u8>>;

fn create_readable_stream(reader: ReadHalf<TlsStream<WsIo>>) -> web_sys::ReadableStream {
    let reader = Rc::new(RefCell::new(reader));
    let underlying_source = Object::new();

    let reader_clone = reader.clone();
    let pull = Closure::wrap(
        Box::new(move |controller: ReadableStreamDefaultController| {
            let reader = reader_clone.clone();
            let promise = wasm_bindgen_futures::future_to_promise(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut reader_ref = reader.borrow_mut();
                match reader_ref.read(&mut buf).await {
                    Ok(0) => {
                        controller.close().ok();
                    }
                    Ok(n) => {
                        let chunk = Uint8Array::from(&buf[..n]);
                        controller.enqueue_with_chunk(&chunk.into()).ok();
                    }
                    Err(e) => {
                        let error = JsValue::from_str(&e.to_string());
                        controller.error_with_e(&error);
                    }
                }
                Ok(JsValue::UNDEFINED)
            });
            promise
        }) as Box<dyn FnMut(ReadableStreamDefaultController) -> Promise>,
    );

    Reflect::set(&underlying_source, &"pull".into(), pull.as_ref()).unwrap();
    pull.forget();

    web_sys::ReadableStream::new_with_underlying_source(&underlying_source).unwrap()
}

/// Attestation result summary exposed to JavaScript.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationSummary {
    pub trusted: bool,
    pub tee_type: String,
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
}

fn summarize(report: &Report) -> AttestationSummary {
    match report {
        Report::Tdx(verified) => AttestationSummary {
            trusted: true,
            tee_type: "Tdx".to_string(),
            tcb_status: verified.status.clone(),
            advisory_ids: verified.advisory_ids.clone(),
        },
    }
}

/// An attested TLS stream over a WebSocket connection.
///
/// Provides a native `ReadableStream` for response data and a `send` method
/// for writing requests. This design allows zero-copy response streaming
/// while keeping the write path simple.
///
/// Re-attestation is not supported on this low-level stream: the pull-based
/// `ReadableStream` may hold a pending read, and the caller owns the
/// application protocol framing, so an in-band quote exchange could
/// interleave with application traffic. Use [`AtlsHttp`] for long-lived
/// connections with transparent re-attestation, or reconnect periodically
/// (every connect performs a full attestation).
#[wasm_bindgen]
pub struct AttestedStream {
    writer: Rc<RefCell<Option<WriteHalf<TlsStream<WsIo>>>>>,
    attestation: AttestationSummary,
    readable: web_sys::ReadableStream,
}

#[wasm_bindgen]
impl AttestedStream {
    /// Connect to a TEE server via WebSocket proxy and perform aTLS protocol.
    ///
    /// Returns an AttestedStream with:
    /// - `readable`: Native ReadableStream for response data
    /// - `send(data)`: Method to write request data
    /// - `attestation()`: Attestation verification result
    ///
    /// # Arguments
    /// * `ws_url` - WebSocket URL (e.g., "ws://proxy:9000?target=host:443")
    /// * `server_name` - TLS server name for SNI
    /// * `policy` - Verification policy
    #[wasm_bindgen(js_name = connect)]
    pub async fn connect(
        ws_url: &str,
        server_name: &str,
        policy_js: JsValue,
    ) -> Result<AttestedStream, JsValue> {
        // Parse policy from JS object
        let policy: Policy = serde_wasm_bindgen::from_value(policy_js)
            .map_err(|e| JsValue::from_str(&format!("invalid policy: {e}")))?;

        // 1. Establish WebSocket tunnel
        let (_meta, ws_stream) = WsMeta::connect(ws_url, None)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // 2. Perform aTLS protocol
        let (tls, report) = atls_connect(
            ws_stream.into_io(),
            server_name,
            policy,
            Some(vec!["http/1.1".into()]),
        )
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let (reader, writer) = tls.split();

        let readable = create_readable_stream(reader);

        Ok(AttestedStream {
            writer: Rc::new(RefCell::new(Some(writer))),
            attestation: summarize(&report),
            readable,
        })
    }

    /// Get the native ReadableStream for response data.
    ///
    /// This stream can be passed directly to `new Response(readable)`.
    #[wasm_bindgen(getter)]
    pub fn readable(&self) -> web_sys::ReadableStream {
        self.readable.clone()
    }

    /// Get the attestation result from the aTLS protocol.
    #[wasm_bindgen(js_name = attestation)]
    pub fn attestation(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.attestation)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Send data to the TEE over the attested TLS connection.
    #[wasm_bindgen(js_name = send)]
    pub async fn send(&self, data: &[u8]) -> Result<(), JsValue> {
        let mut writer_opt = self.writer.borrow_mut();
        let writer = writer_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("stream is closed"))?;

        writer
            .write_all(data)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        writer
            .flush()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Close the write side of the stream.
    #[wasm_bindgen(js_name = closeWrite)]
    pub async fn close_write(&self) -> Result<(), JsValue> {
        let mut writer_opt = self.writer.borrow_mut();
        if let Some(mut writer) = writer_opt.take() {
            writer
                .close()
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }
        Ok(())
    }
}

// ============================================================================
// HTTP Client using hyper (secure, battle-tested HTTP/1.1 implementation)
// ============================================================================

use hyper::client::conn::http1::SendRequest;

/// High-level HTTP client over attested TLS using hyper.
///
/// This implementation uses hyper's HTTP/1.1 client connection API which:
/// - Prevents CRLF injection attacks through proper header validation
/// - Correctly handles all transfer encodings (chunked, content-length, close-delimited)
/// - Is a battle-tested, widely-used HTTP implementation
/// - Supports connection reuse via HTTP/1.1 keep-alive
#[wasm_bindgen]
pub struct AtlsHttp {
    /// The hyper HTTP/1.1 sender - can make multiple requests on the same connection.
    /// Stored as Option to allow detecting when the connection is closed.
    sender: Rc<RefCell<Option<SendRequest<Full<Bytes>>>>>,
    /// Latest attestation result; refreshed by `reattest()`.
    attestation: RefCell<AttestationSummary>,
    /// Re-attestation handle retaining the verifier, session peer
    /// certificate, and session EKM (captured before hyper consumed the
    /// stream — the raw stream is unreachable afterwards).
    reattester: Rc<Reattester>,
}

#[wasm_bindgen]
impl AtlsHttp {
    /// Connect to a TEE server and perform aTLS protocol.
    ///
    /// This establishes an HTTP/1.1 connection that can be reused for multiple requests.
    /// The connection uses HTTP keep-alive by default.
    ///
    /// # Arguments
    /// * `ws_url` - WebSocket URL (e.g., "ws://proxy:9000?target=host:443")
    /// * `server_name` - TLS server name for SNI
    /// * `policy` - Verification policy
    #[wasm_bindgen(js_name = connect)]
    pub async fn connect(
        ws_url: &str,
        server_name: &str,
        policy_js: JsValue,
    ) -> Result<AtlsHttp, JsValue> {
        // Parse policy from JS object
        let policy: Policy = serde_wasm_bindgen::from_value(policy_js)
            .map_err(|e| JsValue::from_str(&format!("invalid policy: {e}")))?;

        let (_meta, ws_stream) = WsMeta::connect(ws_url, None)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let (tls, report, reattester) = atls_connect_with_reattester(
            ws_stream.into_io(),
            server_name,
            policy,
            Some(vec!["http/1.1".into()]),
        )
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let attestation = summarize(&report);

        // Wrap TLS stream for hyper compatibility
        let io = HyperIo::new(tls);

        // Perform HTTP/1.1 handshake with hyper
        let (sender, conn) = http1::handshake(io)
            .await
            .map_err(|e| JsValue::from_str(&format!("HTTP handshake failed: {e}")))?;

        // Spawn the connection driver in the background
        // This handles the actual HTTP protocol I/O and keeps the connection alive
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = conn.await {
                // Log connection errors (in WASM, we can't easily propagate these)
                web_sys::console::warn_1(&JsValue::from_str(&format!(
                    "HTTP connection error: {e}"
                )));
            }
        });

        Ok(AtlsHttp {
            sender: Rc::new(RefCell::new(Some(sender))),
            attestation: RefCell::new(attestation),
            reattester: Rc::new(reattester),
        })
    }

    /// Get the latest attestation result (refreshed by `reattest()`).
    #[wasm_bindgen(js_name = attestation)]
    pub fn attestation(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&*self.attestation.borrow())
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Whether the connection's attestation evidence is older than the
    /// policy's `reattestation_interval_secs`.
    ///
    /// Always false when re-attestation is disabled (interval 0).
    #[wasm_bindgen(js_name = isReattestationDue)]
    pub fn is_reattestation_due(&self) -> bool {
        self.reattester.is_due()
    }

    /// Re-attest the connection over the live HTTP/1.1 session.
    ///
    /// Sends a `POST /tdx_quote` request with a fresh nonce through the same
    /// hyper connection and runs the full verification pipeline on the
    /// response (`report_data = SHA512(nonce || session_ekm)` binds it to
    /// this session). The connection must be idle — check `isReady()` first,
    /// like `fetch()`.
    ///
    /// On success the stored attestation is refreshed and returned. On
    /// failure the evidence stays stale and the connection must be closed
    /// and replaced (fail closed); a fresh connect performs a full
    /// attestation.
    #[wasm_bindgen(js_name = reattest)]
    pub async fn reattest(&self) -> Result<JsValue, JsValue> {
        let request = self.reattester.begin();
        let body_json = request.body_json();

        // Mirrors fetch(): the sender borrow is held for the exchange, so a
        // concurrent fetch()/reattest() is serialized by the JS caller via
        // isReady(), exactly like concurrent fetch()+fetch().
        let mut sender_guard = self.sender.borrow_mut();
        let sender = sender_guard
            .as_mut()
            .ok_or_else(|| JsValue::from_str("connection closed"))?;

        if !sender.is_ready() {
            return Err(JsValue::from_str(
                "connection busy - wait for previous response to complete",
            ));
        }

        let http_request = Request::builder()
            .method(ReattestRequest::method())
            .uri(ReattestRequest::path())
            .header("Host", self.reattester.server_name())
            .header("Content-Type", ReattestRequest::content_type())
            .header("Content-Length", body_json.len().to_string())
            .body(Full::new(Bytes::from(body_json)))
            .map_err(|e| JsValue::from_str(&format!("Failed to build request: {e}")))?;

        let response = sender
            .send_request(http_request)
            .await
            .map_err(|e| JsValue::from_str(&format!("reattestation failed: {e}")))?;

        let status = response.status();
        if status != hyper::StatusCode::OK {
            return Err(JsValue::from_str(&format!(
                "reattestation failed: /tdx_quote returned HTTP {status}"
            )));
        }

        // Collect the response body (hyper strips chunked framing).
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| JsValue::from_str(&format!("reattestation failed: {e}")))?
            .to_bytes();
        drop(sender_guard);

        // No RefCell borrow is held across this await (Reattester is &self).
        // `finish` consumes the request: this exchange cannot be replayed.
        let report = self
            .reattester
            .finish(request, &body_bytes)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let summary = summarize(&report);
        *self.attestation.borrow_mut() = summary.clone();
        serde_wasm_bindgen::to_value(&summary).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Check if the connection is ready for another request.
    ///
    /// Returns true if the connection can accept a new request, false if closed or busy.
    #[wasm_bindgen(js_name = isReady)]
    pub fn is_ready(&self) -> bool {
        self.sender
            .borrow()
            .as_ref()
            .map(|s| s.is_ready())
            .unwrap_or(false)
    }

    /// Close the connection explicitly.
    #[wasm_bindgen(js_name = close)]
    pub fn close(&self) {
        self.sender.borrow_mut().take();
    }

    /// Perform an HTTP request and return response with streaming body.
    ///
    /// Returns a JS object: { status, statusText, headers, body }
    /// where body is a native ReadableStream.
    ///
    /// This method uses hyper's HTTP/1.1 client which properly validates
    /// headers (preventing CRLF injection) and handles transfer encodings.
    ///
    /// The connection can be reused for subsequent requests after the response
    /// body is fully consumed. Use `isReady()` to check availability.
    #[wasm_bindgen(js_name = fetch)]
    pub async fn fetch(
        &self,
        method: &str,
        path: &str,
        host: &str,
        headers_js: JsValue,
        body: Option<Vec<u8>>,
    ) -> Result<JsValue, JsValue> {
        // Borrow the sender mutably to send the request
        // We don't take() it - the connection stays alive for reuse
        let mut sender_guard = self.sender.borrow_mut();
        let sender = sender_guard
            .as_mut()
            .ok_or_else(|| JsValue::from_str("connection closed"))?;

        // Check if the connection is ready (not busy with another request)
        if !sender.is_ready() {
            return Err(JsValue::from_str(
                "connection busy - wait for previous response to complete",
            ));
        }

        // Parse headers from JS
        let custom_headers: Vec<(String, String)> =
            if headers_js.is_null() || headers_js.is_undefined() {
                vec![]
            } else {
                serde_wasm_bindgen::from_value(headers_js)
                    .map_err(|e| JsValue::from_str(&format!("Invalid headers: {e}")))?
            };

        // Build HTTP request using hyper's type-safe Request builder
        // This prevents CRLF injection as hyper validates header names and values
        let path = if path.is_empty() { "/" } else { path };

        let body_bytes = body.unwrap_or_default();
        let body = Full::new(Bytes::from(body_bytes.clone()));

        // Note: We intentionally do NOT set "Connection: close" here
        // This allows HTTP/1.1 keep-alive for connection reuse
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", host);

        // Add custom headers (hyper will validate them)
        for (name, value) in &custom_headers {
            let name_lower = name.to_lowercase();
            // Don't allow overriding Host, but allow Connection if user wants to close
            if name_lower != "host" {
                builder = builder.header(name.as_str(), value.as_str());
            }
        }

        // Add Content-Length for non-empty bodies
        if !body_bytes.is_empty() {
            builder = builder.header("Content-Length", body_bytes.len().to_string());
        }

        let request = builder
            .body(body)
            .map_err(|e| JsValue::from_str(&format!("Failed to build request: {e}")))?;

        // Send the request using hyper
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| JsValue::from_str(&format!("Request failed: {e}")))?;

        // Extract response parts
        let status = response.status().as_u16();
        let status_text = response
            .status()
            .canonical_reason()
            .unwrap_or("")
            .to_string();

        // Build headers object
        let headers_obj = Object::new();
        for (name, value) in response.headers() {
            let value_str = value.to_str().unwrap_or("");
            Reflect::set(
                &headers_obj,
                &name.as_str().into(),
                &JsValue::from_str(value_str),
            )?;
        }

        // Create ReadableStream from hyper body
        // hyper handles chunked decoding automatically!
        // Note: The connection becomes ready for reuse after the body is fully consumed
        let body_stream = create_hyper_body_stream(response.into_body());

        // Build JS response object
        let result = Object::new();
        Reflect::set(&result, &"status".into(), &JsValue::from(status))?;
        Reflect::set(
            &result,
            &"statusText".into(),
            &JsValue::from_str(&status_text),
        )?;
        Reflect::set(&result, &"headers".into(), &headers_obj)?;
        Reflect::set(&result, &"body".into(), &body_stream)?;

        Ok(result.into())
    }
}

/// Create a ReadableStream from a hyper body.
///
/// hyper automatically handles chunked transfer decoding, so we just
/// need to iterate over the body frames.
fn create_hyper_body_stream(body: hyper::body::Incoming) -> web_sys::ReadableStream {
    let body = Rc::new(RefCell::new(Some(body)));
    let underlying_source = Object::new();

    let pull = Closure::wrap(
        Box::new(move |controller: ReadableStreamDefaultController| {
            let body = body.clone();

            wasm_bindgen_futures::future_to_promise(async move {
                let mut body_opt = body.borrow_mut();

                if let Some(body_inner) = body_opt.as_mut() {
                    // Try to get the next frame from the body
                    match body_inner.frame().await {
                        Some(Ok(frame)) => {
                            if let Some(data) = frame.data_ref() {
                                let arr = Uint8Array::from(data.as_ref());
                                controller.enqueue_with_chunk(&arr.into()).ok();
                            }
                            // If it's a trailers frame, we ignore it
                        }
                        Some(Err(e)) => {
                            let error = JsValue::from_str(&format!("Body read error: {e}"));
                            controller.error_with_e(&error);
                        }
                        None => {
                            // Body complete
                            controller.close().ok();
                        }
                    }
                } else {
                    controller.close().ok();
                }

                Ok(JsValue::UNDEFINED)
            })
        }) as Box<dyn FnMut(ReadableStreamDefaultController) -> Promise>,
    );

    Reflect::set(&underlying_source, &"pull".into(), pull.as_ref()).unwrap();
    pull.forget();

    web_sys::ReadableStream::new_with_underlying_source(&underlying_source).unwrap()
}

#[cfg(all(target_arch = "wasm32", test))]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    // Tests can run in both browser and Node.js
    // Remove run_in_browser to allow Node.js execution

    #[wasm_bindgen_test]
    fn test_attestation_summary_serialization() {
        let summary = AttestationSummary {
            trusted: true,
            tee_type: "Tdx".to_string(),
            tcb_status: "UpToDate".to_string(),
            advisory_ids: vec!["INTEL-SA-00001".to_string()],
        };

        // Test that it can be serialized to JSON
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"trusted\":true"));
        assert!(json.contains("\"teeType\":\"Tdx\""));
        assert!(json.contains("\"tcbStatus\":\"UpToDate\""));
        assert!(json.contains("INTEL-SA-00001"));
    }

    #[wasm_bindgen_test]
    fn test_attestation_summary_camel_case() {
        let summary = AttestationSummary {
            trusted: false,
            tee_type: "Snp".to_string(),
            tcb_status: "SWHardeningNeeded".to_string(),
            advisory_ids: vec![],
        };

        let json = serde_json::to_string(&summary).unwrap();
        // Verify camelCase renaming is applied
        assert!(json.contains("teeType"));
        assert!(json.contains("tcbStatus"));
        assert!(json.contains("advisoryIds"));
        // Verify snake_case is NOT present
        assert!(!json.contains("tee_type"));
        assert!(!json.contains("tcb_status"));
        assert!(!json.contains("advisory_ids"));
    }

    #[wasm_bindgen_test]
    fn test_attestation_summary_to_js_value() {
        let summary = AttestationSummary {
            trusted: true,
            tee_type: "Tdx".to_string(),
            tcb_status: "UpToDate".to_string(),
            advisory_ids: vec!["ADV1".to_string(), "ADV2".to_string()],
        };

        // Test conversion to JsValue via serde-wasm-bindgen
        let js_value = serde_wasm_bindgen::to_value(&summary).unwrap();
        assert!(!js_value.is_undefined());
        assert!(!js_value.is_null());
    }

    #[wasm_bindgen_test]
    fn test_attestation_summary_empty_advisories() {
        let summary = AttestationSummary {
            trusted: true,
            tee_type: "Tdx".to_string(),
            tcb_status: "UpToDate".to_string(),
            advisory_ids: vec![],
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"advisoryIds\":[]"));
    }
}
