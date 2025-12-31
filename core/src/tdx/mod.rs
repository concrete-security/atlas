//! TDX verifier implementation for dstack.

pub mod config;

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use dcap_qvl::collateral::get_collateral_and_verify;
use dcap_qvl::verify::VerifiedReport;
use dstack_sdk_types::dstack::{EventLog, GetQuoteResponse, TcbInfo};
use sha2::{Digest, Sha256};

use crate::compose_hash::get_compose_hash;
use crate::error::RatlsVerificationError;
use crate::verifier::{AsyncByteStream, AsyncReadExt, AsyncWriteExt, RatlsVerifier};

pub use config::{DstackTDXVerifierBuilder, DstackTDXVerifierConfig, ExpectedBootchain};

/// Response from the /tdx_quote endpoint.
#[derive(Debug, serde::Deserialize)]
struct QuoteEndpointResponse {
    quote: GetQuoteResponse,
    tcb_info: TcbInfo,
}

/// DstackTDXVerifier performs TDX attestation verification for dstack deployments.
///
/// This verifier implements the full verification flow:
/// 1. Fetch quote from remote server
/// 2. Verify DCAP quote using Intel PCS
/// 3. Verify certificate binding to event log
/// 4. Verify RTMR replay
/// 5. Verify bootchain measurements (MRTD, RTMR0-2)
/// 6. Verify app compose hash
/// 7. Verify OS image hash
pub struct DstackTDXVerifier {
    config: DstackTDXVerifierConfig,
    /// Cached verified report (if cache_collateral is true)
    cached_report: Arc<RwLock<Option<VerifiedReport>>>,
}

impl DstackTDXVerifier {
    /// Create a new DstackTDXVerifier with the given configuration.
    pub fn new(config: DstackTDXVerifierConfig) -> Result<Self, RatlsVerificationError> {
        // Validation: bootchain and os_image_hash must be provided together
        if !config.disable_runtime_verification {
            if config.expected_bootchain.is_none() || config.os_image_hash.is_none() {
                return Err(RatlsVerificationError::Configuration(
                    "expected_bootchain and os_image_hash must be provided together".into(),
                ));
            }
            if config.app_compose.is_none() {
                return Err(RatlsVerificationError::Configuration(
                    "app_compose must be provided".into(),
                ));
            }
        }
        Ok(Self {
            config,
            cached_report: Arc::new(RwLock::new(None)),
        })
    }

    /// Create a new builder for DstackTDXVerifier.
    pub fn builder() -> DstackTDXVerifierBuilder {
        DstackTDXVerifierBuilder::new()
    }

    /// Verify quote using dcap-qvl directly.
    async fn verify_quote(&self, quote: &[u8]) -> Result<VerifiedReport, RatlsVerificationError> {
        let pccs_url = self.config.pccs_url.as_deref();

        let report = get_collateral_and_verify(quote, pccs_url)
            .await
            .map_err(|e| RatlsVerificationError::Quote(format!("DCAP verification failed: {}", e)))?;

        // Check TCB status
        if !self
            .config
            .allowed_tcb_status
            .iter()
            .any(|s| s == &report.status)
        {
            return Err(RatlsVerificationError::TcbStatusNotAllowed {
                status: report.status.clone(),
                allowed: self.config.allowed_tcb_status.clone(),
            });
        }

        // Cache if enabled
        if self.config.cache_collateral {
            if let Ok(mut guard) = self.cached_report.write() {
                *guard = Some(report.clone());
            }
        }

        Ok(report)
    }

    /// Verify bootchain measurements (MRTD, RTMR0-2) using TcbInfo from dstack-sdk.
    fn verify_bootchain(&self, tcb_info: &TcbInfo) -> Result<(), RatlsVerificationError> {
        let bootchain = match &self.config.expected_bootchain {
            Some(b) => b,
            None => return Ok(()), // Skip if not configured
        };

        // Check MRTD (TcbInfo fields are already strings)
        if tcb_info.mrtd != bootchain.mrtd {
            return Err(RatlsVerificationError::BootchainMismatch {
                field: "mrtd".into(),
                expected: bootchain.mrtd.clone(),
                actual: tcb_info.mrtd.clone(),
            });
        }

        // Check RTMR0-2
        let rtmrs = [
            (&bootchain.rtmr0, &tcb_info.rtmr0, 0u8),
            (&bootchain.rtmr1, &tcb_info.rtmr1, 1),
            (&bootchain.rtmr2, &tcb_info.rtmr2, 2),
        ];
        for (expected, actual, idx) in rtmrs {
            if expected != actual {
                return Err(RatlsVerificationError::RtmrMismatch {
                    index: idx,
                    expected: expected.clone(),
                    actual: actual.clone(),
                });
            }
        }
        Ok(())
    }

    /// Verify certificate is in event log (using dstack-sdk EventLog type).
    fn verify_cert_in_eventlog(&self, cert_der: &[u8], events: &[EventLog]) -> bool {
        let cert_hash = hex::encode(Sha256::digest(cert_der));

        // Find last "New TLS Certificate" event
        let cert_event = events
            .iter()
            .rfind(|e| e.event == "New TLS Certificate");

        match cert_event {
            Some(event) => {
                // event_payload is hex-encoded, decode it to get the cert hash string
                // Format: hex_encode(cert_hash_string.encode()) -> decode to get cert_hash_string
                match hex::decode(&event.event_payload) {
                    Ok(decoded) => {
                        match String::from_utf8(decoded) {
                            Ok(eventlog_cert_hash) => eventlog_cert_hash == cert_hash,
                            Err(_) => false,
                        }
                    }
                    Err(_) => false,
                }
            }
            None => false,
        }
    }

    /// Verify app compose hash using TcbInfo from dstack-sdk.
    fn verify_app_compose(
        &self,
        tcb_info: &TcbInfo,
        events: &[EventLog],
    ) -> Result<(), RatlsVerificationError> {
        let expected = match &self.config.app_compose {
            Some(ac) => get_compose_hash(ac),
            None => return Ok(()),
        };

        // First check against TcbInfo.compose_hash (string field)
        if tcb_info.compose_hash != expected {
            return Err(RatlsVerificationError::AppComposeHashMismatch {
                expected: expected.clone(),
                actual: tcb_info.compose_hash.clone(),
            });
        }

        // Then verify against event log
        let event = events.iter().find(|e| e.event == "compose-hash");
        if let Some(e) = event {
            if e.event_payload != expected {
                return Err(RatlsVerificationError::AppComposeHashMismatch {
                    expected,
                    actual: e.event_payload.clone(),
                });
            }
        }
        Ok(())
    }

    /// Verify OS image hash using TcbInfo from dstack-sdk.
    fn verify_os_image_hash(
        &self,
        tcb_info: &TcbInfo,
        events: &[EventLog],
    ) -> Result<(), RatlsVerificationError> {
        let expected = match &self.config.os_image_hash {
            Some(h) => h,
            None => return Ok(()),
        };

        // Check against TcbInfo.os_image_hash (string field)
        if !tcb_info.os_image_hash.is_empty() && &tcb_info.os_image_hash != expected {
            return Err(RatlsVerificationError::OsImageHashMismatch {
                expected: expected.clone(),
                actual: Some(tcb_info.os_image_hash.clone()),
            });
        }

        // Check against event log
        let event = events.iter().find(|e| e.event == "os-image-hash");
        if let Some(e) = event {
            if &e.event_payload != expected {
                return Err(RatlsVerificationError::OsImageHashMismatch {
                    expected: expected.clone(),
                    actual: Some(e.event_payload.clone()),
                });
            }
        }
        Ok(())
    }

    /// Verify RTMR replay using dstack-sdk's built-in replay_rtmrs().
    fn verify_rtmr_replay(
        &self,
        quote_response: &GetQuoteResponse,
        tcb_info: &TcbInfo,
    ) -> Result<(), RatlsVerificationError> {
        // Use dstack-sdk-types' built-in replay_rtmrs()
        let replayed: BTreeMap<u8, String> = quote_response
            .replay_rtmrs()
            .map_err(RatlsVerificationError::Other)?;

        let expected = [
            &tcb_info.rtmr0,
            &tcb_info.rtmr1,
            &tcb_info.rtmr2,
            &tcb_info.rtmr3,
        ];
        for i in 0..4u8 {
            let replayed_rtmr = replayed.get(&i).cloned().unwrap_or_default();
            if &replayed_rtmr != expected[i as usize] {
                return Err(RatlsVerificationError::RtmrMismatch {
                    index: i,
                    expected: expected[i as usize].clone(),
                    actual: replayed_rtmr,
                });
            }
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl RatlsVerifier for DstackTDXVerifier {
    type Report = VerifiedReport;

    async fn verify<S>(
        &self,
        stream: &mut S,
        peer_cert: &[u8],
        hostname: &str,
    ) -> Result<Self::Report, RatlsVerificationError>
    where
        S: AsyncByteStream + Send,
    {
        // 1. Generate nonce and get quote via HTTP POST to /tdx_quote
        let mut report_data = [0u8; 64];
        rand::Rng::fill(&mut rand::thread_rng(), &mut report_data);
        let (quote_response, tcb_info) = get_quote_over_http(stream, &report_data, hostname).await?;

        // 2. Parse event log using dstack-sdk-types
        let events = quote_response
            .decode_event_log()
            .map_err(|e| RatlsVerificationError::Other(e.into()))?;

        // 3. Verify certificate in event log
        if !self.verify_cert_in_eventlog(peer_cert, &events) {
            return Err(RatlsVerificationError::CertificateNotInEventLog);
        }

        // 4. Verify DCAP quote using dcap-qvl directly
        let quote_bytes = quote_response
            .decode_quote()
            .map_err(|e| RatlsVerificationError::Other(anyhow::anyhow!("Failed to decode quote: {}", e)))?;

        // Async quote verification - no blocking!
        let verified_report = self.verify_quote(&quote_bytes).await?;

        // 5. Verify RTMR replay using dstack-sdk's replay_rtmrs()
        self.verify_rtmr_replay(&quote_response, &tcb_info)?;

        // Skip remaining checks if runtime verification is disabled
        if self.config.disable_runtime_verification {
            return Ok(verified_report);
        }

        // 6. Verify bootchain (MRTD, RTMR0-2)
        self.verify_bootchain(&tcb_info)?;

        // 7. Verify app compose hash
        self.verify_app_compose(&tcb_info, &events)?;

        // 8. Verify OS image hash
        self.verify_os_image_hash(&tcb_info, &events)?;

        Ok(verified_report)
    }
}

#[cfg(target_arch = "wasm32")]
impl RatlsVerifier for DstackTDXVerifier {
    type Report = VerifiedReport;

    async fn verify<S>(
        &self,
        stream: &mut S,
        peer_cert: &[u8],
        hostname: &str,
    ) -> Result<Self::Report, RatlsVerificationError>
    where
        S: AsyncByteStream,
    {
        // 1. Generate nonce and get quote via HTTP POST to /tdx_quote
        let mut report_data = [0u8; 64];
        rand::Rng::fill(&mut rand::thread_rng(), &mut report_data);
        let (quote_response, tcb_info) = get_quote_over_http(stream, &report_data, hostname).await?;

        // 2. Parse event log using dstack-sdk-types
        let events = quote_response
            .decode_event_log()
            .map_err(|e| RatlsVerificationError::Other(e.into()))?;

        // 3. Verify certificate in event log
        if !self.verify_cert_in_eventlog(peer_cert, &events) {
            return Err(RatlsVerificationError::CertificateNotInEventLog);
        }

        // 4. Verify DCAP quote using dcap-qvl directly
        let quote_bytes = quote_response
            .decode_quote()
            .map_err(|e| RatlsVerificationError::Other(anyhow::anyhow!("Failed to decode quote: {}", e)))?;

        // Async quote verification - no blocking!
        let verified_report = self.verify_quote(&quote_bytes).await?;

        // 5. Verify RTMR replay using dstack-sdk's replay_rtmrs()
        self.verify_rtmr_replay(&quote_response, &tcb_info)?;

        // Skip remaining checks if runtime verification is disabled
        if self.config.disable_runtime_verification {
            return Ok(verified_report);
        }

        // 6. Verify bootchain (MRTD, RTMR0-2)
        self.verify_bootchain(&tcb_info)?;

        // 7. Verify app compose hash
        self.verify_app_compose(&tcb_info, &events)?;

        // 8. Verify OS image hash
        self.verify_os_image_hash(&tcb_info, &events)?;

        Ok(verified_report)
    }
}

/// Fetch quote over HTTP from /tdx_quote endpoint (async version).
async fn get_quote_over_http<S>(
    stream: &mut S,
    report_data: &[u8; 64],
    hostname: &str,
) -> Result<(GetQuoteResponse, TcbInfo), RatlsVerificationError>
where
    S: AsyncByteStream,
{
    // Build HTTP POST request for the /tdx_quote endpoint
    let body = serde_json::json!({
        "report_data_hex": hex::encode(report_data)
    });
    let body_str = body.to_string();

    let request = format!(
        "POST /tdx_quote HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         {}",
        hostname,
        body_str.len(),
        body_str
    );

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| RatlsVerificationError::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| RatlsVerificationError::Io(e.to_string()))?;

    // Read HTTP response
    let mut response_buf = Vec::new();
    let mut chunk = [0u8; 4096];

    // Read until we have the complete response
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| RatlsVerificationError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        response_buf.extend_from_slice(&chunk[..n]);

        // Check if we have the complete response (look for end of body)
        if let Some(body_start) = find_http_body_start(&response_buf) {
            // Try to parse content-length header
            if let Some(content_length) = parse_content_length(&response_buf[..body_start]) {
                if response_buf.len() >= body_start + content_length {
                    break;
                }
            }
        }
    }

    // Parse HTTP response
    let body_start = find_http_body_start(&response_buf)
        .ok_or_else(|| RatlsVerificationError::Io("Invalid HTTP response".into()))?;
    let response_body = &response_buf[body_start..];

    let response: QuoteEndpointResponse = serde_json::from_slice(response_body)
        .map_err(|e| RatlsVerificationError::Other(e.into()))?;

    Ok((response.quote, response.tcb_info))
}

/// Find the start of HTTP body (after \r\n\r\n).
fn find_http_body_start(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

/// Parse Content-Length header from HTTP response.
fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let headers_str = std::str::from_utf8(headers).ok()?;
    for line in headers_str.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            let value = line.split(':').nth(1)?.trim();
            return value.parse().ok();
        }
    }
    None
}
