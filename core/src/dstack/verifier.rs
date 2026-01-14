//! DstackTDXVerifier implementation.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use dcap_qvl::collateral::get_collateral;
use dcap_qvl::quote::Quote;
use dcap_qvl::verify::{verify, VerifiedReport};
use dcap_qvl::QuoteCollateralV3;
use dstack_sdk_types::dstack::{EventLog, GetQuoteResponse};
use log::{debug, warn};
use sha2::{Digest, Sha256};

use crate::dstack::compose_hash::get_compose_hash;
use crate::dstack::config::DstackTDXVerifierConfig;
use crate::error::RatlsVerificationError;
use crate::verifier::{AsyncByteStream, AsyncReadExt, AsyncWriteExt, RatlsVerifier, Report};

pub use crate::dstack::config::DstackTDXVerifierBuilder;

/// Cache key for collateral: (pccs_url, fmspc, ca)
type CollateralCacheKey = (String, String, &'static str);

/// Cached collateral with timestamp for TTL expiration.
#[derive(Clone)]
struct CachedCollateral {
    collateral: QuoteCollateralV3,
    cached_at_secs: u64,
}

/// Default collateral cache TTL: 8 hours (in seconds).
const COLLATERAL_CACHE_TTL_SECS: u64 = 8 * 3600;

/// Response from the /tdx_quote endpoint.
#[derive(Debug, serde::Deserialize)]
struct QuoteEndpointResponse {
    quote: GetQuoteResponse,
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
    /// Cached collateral keyed by (pccs_url, fmspc, ca) with TTL expiration.
    cached_collateral: Arc<RwLock<HashMap<CollateralCacheKey, CachedCollateral>>>,
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
            cached_collateral: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create a new builder for DstackTDXVerifier.
    pub fn builder() -> DstackTDXVerifierBuilder {
        DstackTDXVerifierBuilder::new()
    }

    /// Verify quote using dcap-qvl directly.
    async fn verify_quote(&self, quote: &[u8]) -> Result<VerifiedReport, RatlsVerificationError> {
        let pccs_url = self.config.pccs_url.as_deref().unwrap_or_default();
        let pccs_url = if pccs_url.is_empty() {
            "https://api.trustedservices.intel.com"
        } else {
            pccs_url
        };

        // Parse quote to get cache key components (FMSPC and CA)
        let parsed_quote = Quote::parse(quote)
            .map_err(|e| RatlsVerificationError::Quote(format!("Failed to parse quote: {}", e)))?;
        let fmspc = hex::encode_upper(
            parsed_quote
                .fmspc()
                .map_err(|e| RatlsVerificationError::Quote(format!("Failed to get FMSPC: {}", e)))?,
        );
        let ca = parsed_quote
            .ca()
            .map_err(|e| RatlsVerificationError::Quote(format!("Failed to get CA: {}", e)))?;

        let cache_key = (pccs_url.to_string(), fmspc.clone(), ca);

        // Get current time - platform specific (needed for cache TTL and verification)
        #[cfg(not(target_arch = "wasm32"))]
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                RatlsVerificationError::Quote(format!("Failed to get current time: {}", e))
            })?
            .as_secs();

        #[cfg(target_arch = "wasm32")]
        let now_secs = (js_sys::Date::now() / 1000.0) as u64;

        // Try to get collateral from cache (with TTL check)
        let cached = if self.config.cache_collateral {
            match self.cached_collateral.read() {
                Ok(guard) => guard.get(&cache_key).and_then(|entry| {
                    if now_secs.saturating_sub(entry.cached_at_secs) < COLLATERAL_CACHE_TTL_SECS {
                        Some(entry.collateral.clone())
                    } else {
                        debug!("Cached collateral expired for FMSPC={}, CA={}", fmspc, ca);
                        None
                    }
                }),
                Err(_) => {
                    warn!("Collateral cache lock poisoned, treating as cache miss");
                    None
                }
            }
        } else {
            None
        };

        let collateral = match cached {
            Some(c) => {
                debug!(
                    "Using cached collateral for PCCS={}, FMSPC={}, CA={}",
                    pccs_url, fmspc, ca
                );
                c
            }
            None => {
                debug!("Fetching collateral from {}", pccs_url);
                let c = get_collateral(pccs_url, quote)
                    .await
                    .map_err(|e| {
                        RatlsVerificationError::Quote(format!("Failed to get collateral: {}", e))
                    })?;

                // Cache if enabled
                if self.config.cache_collateral {
                    match self.cached_collateral.write() {
                        Ok(mut guard) => {
                            debug!("Caching collateral for FMSPC={}, CA={}", fmspc, ca);
                            guard.insert(cache_key, CachedCollateral {
                                collateral: c.clone(),
                                cached_at_secs: now_secs,
                            });
                        }
                        Err(_) => {
                            warn!("Collateral cache lock poisoned, skipping cache write");
                        }
                    }
                }
                c
            }
        };

        debug!("Collateral received, verifying DCAP quote");

        // Verify the quote
        let report = verify(quote, &collateral, now_secs)
            .map_err(|e| RatlsVerificationError::Quote(format!("DCAP verification failed: {}", e)))?;

        debug!("DCAP verification complete, TCB status: {}", report.status);

        // Check TCB status
        let tcb_allowed = self
            .config
            .allowed_tcb_status
            .iter()
            .any(|s| s == &report.status);

        debug!(
            "TCB status '{}' allowed: {}",
            report.status, tcb_allowed
        );

        if !tcb_allowed {
            return Err(RatlsVerificationError::TcbStatusNotAllowed {
                status: report.status.clone(),
                allowed: self.config.allowed_tcb_status.clone(),
            });
        }

        Ok(report)
    }

    /// Verify bootchain measurements (MRTD, RTMR0-2) using the trusted verified report.
    ///
    /// Compares the cryptographically verified measurements from the report
    /// against the expected bootchain configuration.
    ///
    /// Fails if `expected_bootchain` is not configured.
    fn verify_bootchain(
        &self,
        verified_report: &VerifiedReport,
    ) -> Result<(), RatlsVerificationError> {
        let bootchain = self.config.expected_bootchain.as_ref().ok_or_else(|| {
            RatlsVerificationError::Configuration("expected_bootchain is required".into())
        })?;

        // Get the trusted TD report from DCAP verification
        let td_report = verified_report.report.as_td10().ok_or_else(|| {
            RatlsVerificationError::TeeTypeMismatch(
                "expected TDX report but got SGX enclave report".into(),
            )
        })?;

        debug!("Verifying bootchain measurements against verified report");

        // Check MRTD (convert from bytes to hex string)
        let actual_mrtd = hex::encode(td_report.mr_td);
        debug!("MRTD expected: {}", bootchain.mrtd);
        debug!("MRTD actual:   {}", actual_mrtd);
        let mrtd_match = actual_mrtd == bootchain.mrtd;
        debug!("MRTD match: {}", mrtd_match);

        if !mrtd_match {
            return Err(RatlsVerificationError::BootchainMismatch {
                field: "mrtd".into(),
                expected: bootchain.mrtd.clone(),
                actual: actual_mrtd,
            });
        }

        // Check RTMR0-2 (convert from bytes to hex strings)
        let actual_rtmrs = [
            hex::encode(td_report.rt_mr0),
            hex::encode(td_report.rt_mr1),
            hex::encode(td_report.rt_mr2),
        ];
        let expected_rtmrs = [&bootchain.rtmr0, &bootchain.rtmr1, &bootchain.rtmr2];

        for idx in 0..3usize {
            debug!("RTMR{} expected: {}", idx, expected_rtmrs[idx]);
            debug!("RTMR{} actual:   {}", idx, actual_rtmrs[idx]);
            let rtmr_match = &actual_rtmrs[idx] == expected_rtmrs[idx];
            debug!("RTMR{} match: {}", idx, rtmr_match);

            if !rtmr_match {
                return Err(RatlsVerificationError::BootchainMismatch {
                    field: format!("rtmr{}", idx),
                    expected: expected_rtmrs[idx].clone(),
                    actual: actual_rtmrs[idx].clone(),
                });
            }
        }

        debug!("Bootchain verification successful");
        Ok(())
    }

    /// Verify certificate is in event log (using dstack-sdk EventLog type).
    ///
    /// Returns Ok(true) if cert matches, Ok(false) if cert not found,
    /// or Err if parsing fails.
    fn verify_cert_in_eventlog(
        &self,
        cert_der: &[u8],
        events: &[EventLog],
    ) -> Result<bool, RatlsVerificationError> {
        let cert_hash = hex::encode(Sha256::digest(cert_der));
        debug!("Certificate hash: {}", cert_hash);

        // Find last "New TLS Certificate" event
        let cert_event = events
            .iter()
            .rfind(|e| e.event == "New TLS Certificate");

        match cert_event {
            Some(event) => {
                // event_payload is hex-encoded, decode it to get the cert hash string
                let decoded = hex::decode(&event.event_payload).map_err(|e| {
                    RatlsVerificationError::EventLogParse(format!(
                        "failed to hex-decode certificate event payload: {}",
                        e
                    ))
                })?;

                let eventlog_cert_hash = String::from_utf8(decoded).map_err(|e| {
                    RatlsVerificationError::EventLogParse(format!(
                        "certificate event payload is not valid UTF-8: {}",
                        e
                    ))
                })?;

                debug!("Certificate hash from event log: {}", eventlog_cert_hash);
                let cert_match = eventlog_cert_hash == cert_hash;
                debug!("Certificate hash match: {}", cert_match);
                Ok(cert_match)
            }
            None => {
                debug!("No 'New TLS Certificate' event found in event log");
                Ok(false)
            }
        }
    }

    /// Verify app compose hash using the trusted event log.
    ///
    /// The event log integrity is guaranteed by RTMR replay verification against
    /// the cryptographically verified report.
    ///
    /// Fails if `app_compose` is not configured.
    fn verify_app_compose(&self, events: &[EventLog]) -> Result<(), RatlsVerificationError> {
        let app_compose = self.config.app_compose.as_ref().ok_or_else(|| {
            RatlsVerificationError::Configuration("app_compose is required".into())
        })?;
        let expected = get_compose_hash(app_compose).map_err(|e| {
            RatlsVerificationError::Configuration(format!(
                "Failed to serialize app_compose for hashing: {}",
                e
            ))
        })?;

        debug!("Verifying app compose hash against trusted event log");
        debug!("App compose hash expected: {}", expected);

        // Verify against event log (trusted after RTMR replay verification)
        let event = events
            .iter()
            .find(|e| e.event == "compose-hash")
            .ok_or_else(|| {
                RatlsVerificationError::AppComposeHashMismatch {
                    expected: expected.clone(),
                    actual: "<not found in event log>".to_string(),
                }
            })?;

        debug!("App compose hash from event log: {}", event.event_payload);
        let eventlog_match = event.event_payload == expected;
        debug!("App compose hash match: {}", eventlog_match);

        if !eventlog_match {
            return Err(RatlsVerificationError::AppComposeHashMismatch {
                expected,
                actual: event.event_payload.clone(),
            });
        }

        debug!("App compose verification successful");
        Ok(())
    }

    /// Verify OS image hash using the trusted event log.
    ///
    /// The event log integrity is guaranteed by RTMR replay verification against
    /// the cryptographically verified report.
    ///
    /// Fails if `os_image_hash` is not configured.
    fn verify_os_image_hash(&self, events: &[EventLog]) -> Result<(), RatlsVerificationError> {
        let expected = self.config.os_image_hash.as_ref().ok_or_else(|| {
            RatlsVerificationError::Configuration("os_image_hash is required".into())
        })?;

        debug!("Verifying OS image hash against trusted event log");
        debug!("OS image hash expected: {}", expected);

        // Verify against event log (trusted after RTMR replay verification)
        let event = events
            .iter()
            .find(|e| e.event == "os-image-hash")
            .ok_or_else(|| RatlsVerificationError::OsImageHashMismatch {
                expected: expected.clone(),
                actual: Some("<not found in event log>".to_string()),
            })?;

        debug!("OS image hash from event log: {}", event.event_payload);
        let eventlog_match = &event.event_payload == expected;
        debug!("OS image hash match: {}", eventlog_match);

        if !eventlog_match {
            return Err(RatlsVerificationError::OsImageHashMismatch {
                expected: expected.clone(),
                actual: Some(event.event_payload.clone()),
            });
        }

        debug!("OS image hash verification successful");
        Ok(())
    }

    /// Verify RTMR replay using dstack-sdk's built-in replay_rtmrs().
    ///
    /// Compares replayed RTMRs from the event log against the trusted values
    /// from the cryptographically verified report.
    fn verify_rtmr_replay(
        &self,
        quote_response: &GetQuoteResponse,
        verified_report: &VerifiedReport,
    ) -> Result<(), RatlsVerificationError> {
        debug!("Verifying RTMR replay against verified report");

        // Get the trusted TD report from DCAP verification
        let td_report = verified_report.report.as_td10().ok_or_else(|| {
            RatlsVerificationError::TeeTypeMismatch(
                "expected TDX report but got SGX enclave report".into(),
            )
        })?;

        // Use dstack-sdk-types' built-in replay_rtmrs()
        let replayed: BTreeMap<u8, String> = quote_response
            .replay_rtmrs()
            .map_err(RatlsVerificationError::Other)?;

        // Get trusted RTMRs from verified report (as hex strings)
        let trusted_rtmrs = [
            hex::encode(td_report.rt_mr0),
            hex::encode(td_report.rt_mr1),
            hex::encode(td_report.rt_mr2),
            hex::encode(td_report.rt_mr3),
        ];

        for i in 0..4u8 {
            let replayed_rtmr = replayed.get(&i).cloned().ok_or_else(|| {
                RatlsVerificationError::Quote(format!(
                    "RTMR{} missing from event log replay - malformed event log",
                    i
                ))
            })?;
            debug!(
                "RTMR{} from verified report: {}",
                i, trusted_rtmrs[i as usize]
            );
            debug!("RTMR{} replayed:             {}", i, replayed_rtmr);
            let rtmr_match = replayed_rtmr == trusted_rtmrs[i as usize];
            debug!("RTMR{} replay match: {}", i, rtmr_match);

            if !rtmr_match {
                return Err(RatlsVerificationError::RtmrMismatch {
                    index: i,
                    expected: trusted_rtmrs[i as usize].clone(),
                    actual: replayed_rtmr,
                });
            }
        }

        debug!("RTMR replay verification successful");
        Ok(())
    }

    /// Verify report data (nonce) matches what we sent.
    ///
    /// This prevents replay attacks by ensuring the quote was generated
    /// specifically for this verification request.
    fn verify_report_data(
        &self,
        report_data: &[u8; 64],
        verified_report: &VerifiedReport,
    ) -> Result<(), RatlsVerificationError> {
        debug!("Verifying report data (nonce) against verified report");

        // Get the trusted TD report from DCAP verification
        let td_report = verified_report.report.as_td10().ok_or_else(|| {
            RatlsVerificationError::TeeTypeMismatch(
                "expected TDX report but got SGX enclave report".into(),
            )
        })?;

        let expected = hex::encode(report_data);
        let actual = hex::encode(td_report.report_data);

        debug!("Report data expected: {}", expected);
        debug!("Report data actual:   {}", actual);

        if expected != actual {
            return Err(RatlsVerificationError::ReportDataMismatch { expected, actual });
        }

        debug!("Report data verification successful");
        Ok(())
    }
}

impl RatlsVerifier for DstackTDXVerifier {
    async fn verify<S>(
        &self,
        stream: &mut S,
        peer_cert: &[u8],
        hostname: &str,
    ) -> Result<Report, RatlsVerificationError>
    where
        S: AsyncByteStream,
    {
        debug!("Starting DStack TDX verification for {}", hostname);

        // 1. Generate nonce and get quote via HTTP POST to /tdx_quote
        let mut report_data = [0u8; 64];
        rand::Rng::fill(&mut rand::thread_rng(), &mut report_data);
        let quote_response = get_quote_over_http(stream, &report_data, hostname).await?;

        // 2. Parse event log using dstack-sdk-types
        debug!("Parsing event log");
        let events = quote_response
            .decode_event_log()
            .map_err(|e| RatlsVerificationError::Other(e.into()))?;
        debug!("Event log parsed, {} events found", events.len());

        // 3. Verify certificate in event log
        debug!("Verifying certificate in event log");
        let cert_in_eventlog = self.verify_cert_in_eventlog(peer_cert, &events)?;
        if !cert_in_eventlog {
            return Err(RatlsVerificationError::CertificateNotInEventLog);
        }

        // 4. Verify DCAP quote using dcap-qvl directly
        debug!("Decoding quote for DCAP verification");
        let quote_bytes = quote_response
            .decode_quote()
            .map_err(|e| RatlsVerificationError::Other(anyhow::anyhow!("Failed to decode quote: {}", e)))?;
        debug!("Quote decoded ({} bytes)", quote_bytes.len());

        // Async quote verification - no blocking!
        let verified_report = self.verify_quote(&quote_bytes).await?;

        // 5. Verify report data (nonce) matches what we sent
        self.verify_report_data(&report_data, &verified_report)?;

        // 6. Verify RTMR replay against the verified report
        self.verify_rtmr_replay(&quote_response, &verified_report)?;

        // Skip remaining checks if runtime verification is disabled
        if self.config.disable_runtime_verification {
            debug!("Runtime verification disabled, skipping bootchain/app-compose/os-image checks");
            return Ok(Report::Tdx(verified_report));
        }

        // 7. Verify bootchain (MRTD, RTMR0-2) against verified report
        self.verify_bootchain(&verified_report)?;

        // 8. Verify app compose hash against trusted event log
        self.verify_app_compose(&events)?;

        // 9. Verify OS image hash against trusted event log
        self.verify_os_image_hash(&events)?;

        debug!("DStack TDX verification complete");
        Ok(Report::Tdx(verified_report))
    }
}

/// Fetch quote over HTTP from /tdx_quote endpoint (async version).
async fn get_quote_over_http<S>(
    stream: &mut S,
    report_data: &[u8; 64],
    hostname: &str,
) -> Result<GetQuoteResponse, RatlsVerificationError>
where
    S: AsyncByteStream,
{
    debug!("Sending POST /tdx_quote request to {}", hostname);

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

    debug!("Received quote response ({} bytes)", response_buf.len());

    // Parse HTTP response
    let body_start = find_http_body_start(&response_buf)
        .ok_or_else(|| RatlsVerificationError::Io("Invalid HTTP response".into()))?;
    let response_body = &response_buf[body_start..];

    let response: QuoteEndpointResponse = serde_json::from_slice(response_body)
        .map_err(|e| {
            RatlsVerificationError::Quote(format!(
                "Failed to parse /tdx_quote response: {}",
                e
            ))
        })?;

    Ok(response.quote)
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
