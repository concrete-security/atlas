//! WASM bindings for RA-TLS attested connections.
//!
//! This module provides a minimal API for establishing attested TLS connections
//! from browsers. HTTP handling is done in JavaScript (ratls-fetch.js).

#![cfg(target_arch = "wasm32")]

mod transport;

use ratls_core::{
    platform::{AsyncReadExt, AsyncWriteExt, TlsStream},
    ratls_connect, Policy,
};
use serde::Serialize;
use std::{cell::RefCell, rc::Rc};
use transport::WasmWsStream;
use wasm_bindgen::prelude::*;

/// Attestation result summary exposed to JavaScript.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationSummary {
    pub trusted: bool,
    pub tee_type: String,
    pub tcb_status: String,
}

/// An attested TLS stream over a WebSocket connection.
///
/// This is the only export from the WASM module. HTTP handling
/// is delegated to JavaScript for simplicity.
#[wasm_bindgen]
pub struct AttestedStream {
    stream: Rc<RefCell<Option<TlsStream<WasmWsStream>>>>,
    attestation: AttestationSummary,
}

#[wasm_bindgen]
impl AttestedStream {
    /// Connect to a TEE server via WebSocket proxy and perform RA-TLS handshake.
    ///
    /// # Arguments
    /// * `ws_url` - WebSocket URL (e.g., "ws://proxy:9000?target=host:443")
    /// * `server_name` - TLS server name for SNI
    #[wasm_bindgen(js_name = connect)]
    pub async fn connect(ws_url: &str, server_name: &str) -> Result<AttestedStream, JsValue> {
        let ws = WasmWsStream::connect(ws_url)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let (tls, att) = ratls_connect(
            ws,
            server_name,
            Policy::default(),
            Some(vec!["http/1.1".into()]),
        )
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(AttestedStream {
            stream: Rc::new(RefCell::new(Some(tls))),
            attestation: AttestationSummary {
                trusted: att.trusted,
                tee_type: format!("{:?}", att.tee_type),
                tcb_status: att.tcb_status,
            },
        })
    }

    /// Get the attestation result from the RA-TLS handshake.
    #[wasm_bindgen(js_name = attestation)]
    pub fn attestation(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.attestation)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Write data to the TLS stream.
    #[wasm_bindgen(js_name = write)]
    pub async fn write(&self, data: &[u8]) -> Result<(), JsValue> {
        let mut stream_opt = self.stream.borrow_mut();
        let stream = stream_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("stream is closed"))?;

        stream
            .write_all(data)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        stream
            .flush()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Read data from the TLS stream.
    ///
    /// Returns an empty Uint8Array when the stream is closed.
    #[wasm_bindgen(js_name = read)]
    pub async fn read(&self, max_bytes: Option<u32>) -> Result<Vec<u8>, JsValue> {
        let mut stream_opt = self.stream.borrow_mut();
        let stream = stream_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("stream is closed"))?;

        let size = max_bytes.unwrap_or(8192) as usize;
        let mut buf = vec![0u8; size];

        match stream.read(&mut buf).await {
            Ok(0) => Ok(Vec::new()),
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(e) => Err(JsValue::from_str(&e.to_string())),
        }
    }

    /// Close the TLS stream.
    #[wasm_bindgen(js_name = close)]
    pub async fn close(&self) -> Result<(), JsValue> {
        let mut stream_opt = self.stream.borrow_mut();
        if let Some(mut stream) = stream_opt.take() {
            stream
                .close()
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }
        Ok(())
    }
}
