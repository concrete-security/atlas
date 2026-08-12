//! DstackTDXVerifier implementation.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use dcap_qvl::collateral::get_collateral;
use dcap_qvl::quote::Quote;
use dcap_qvl::verify::{verify, VerifiedReport};
use dcap_qvl::QuoteCollateralV3;
use dstack_sdk_types::dstack::{EventLog, GetQuoteResponse};
use log::{debug, warn};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::dstack::compose_hash::get_compose_hash;
use crate::dstack::config::DstackTDXVerifierConfig;
use crate::error::AtlsVerificationError;
use crate::tdx::grace_period::enforce_grace_period;
use crate::verifier::{AsyncByteStream, AsyncReadExt, AsyncWriteExt, AtlsVerifier, Report};

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

/// Maximum size of the unauthenticated `/tdx_quote` HTTP response headers.
const MAX_QUOTE_RESPONSE_HEADER_SIZE: usize = 64 * 1024;

/// Maximum size of the unauthenticated `/tdx_quote` HTTP response body.
const MAX_QUOTE_RESPONSE_BODY_SIZE: usize = 16 * 1024 * 1024;

/// dstack runtime events are extended into RTMR3 with this event type.
const DSTACK_RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;

/// Response from the /tdx_quote endpoint.
#[derive(Debug, serde::Deserialize)]
struct QuoteEndpointResponse {
    quote: GetQuoteResponse,
}

fn is_dstack_runtime_event(event: &EventLog, name: &str) -> bool {
    event.imr == 3 && event.event_type == DSTACK_RUNTIME_EVENT_TYPE && event.event == name
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
    pub fn new(config: DstackTDXVerifierConfig) -> Result<Self, AtlsVerificationError> {
        // Validation: bootchain and os_image_hash must be provided together
        if !config.disable_runtime_verification {
            if config.expected_bootchain.is_none() || config.os_image_hash.is_none() {
                return Err(AtlsVerificationError::Configuration(
                    "expected_bootchain and os_image_hash must be provided together".into(),
                ));
            }
            if config.app_compose.is_none() {
                return Err(AtlsVerificationError::Configuration(
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
    async fn verify_quote(&self, quote: &[u8]) -> Result<VerifiedReport, AtlsVerificationError> {
        let pccs_url = self.config.pccs_url.as_deref().unwrap_or_default();
        let pccs_url = if pccs_url.is_empty() {
            "https://api.trustedservices.intel.com"
        } else {
            pccs_url
        };

        // Parse quote to get cache key components (FMSPC and CA)
        let parsed_quote = Quote::parse(quote)
            .map_err(|e| AtlsVerificationError::Quote(format!("Failed to parse quote: {}", e)))?;
        let fmspc =
            hex::encode_upper(parsed_quote.fmspc().map_err(|e| {
                AtlsVerificationError::Quote(format!("Failed to get FMSPC: {}", e))
            })?);
        let ca = parsed_quote
            .ca()
            .map_err(|e| AtlsVerificationError::Quote(format!("Failed to get CA: {}", e)))?;

        let cache_key = (pccs_url.to_string(), fmspc.clone(), ca);

        // Get current time - platform specific (needed for cache TTL and verification)
        #[cfg(not(target_arch = "wasm32"))]
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                AtlsVerificationError::Quote(format!("Failed to get current time: {}", e))
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
                let c = get_collateral(pccs_url, quote).await.map_err(|e| {
                    AtlsVerificationError::Quote(format!("Failed to get collateral: {}", e))
                })?;

                // Cache if enabled
                if self.config.cache_collateral {
                    match self.cached_collateral.write() {
                        Ok(mut guard) => {
                            debug!("Caching collateral for FMSPC={}, CA={}", fmspc, ca);
                            guard.insert(
                                cache_key,
                                CachedCollateral {
                                    collateral: c.clone(),
                                    cached_at_secs: now_secs,
                                },
                            );
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
        let report = verify(quote, &collateral, now_secs).map_err(|e| {
            AtlsVerificationError::Quote(format!("DCAP verification failed: {}", e))
        })?;

        debug!("DCAP verification complete, TCB status: {}", report.status);

        // Check TCB status
        let tcb_allowed = self
            .config
            .allowed_tcb_status
            .iter()
            .any(|s| s == &report.status);

        debug!("TCB status '{}' allowed: {}", report.status, tcb_allowed);

        // If TCB status is OutOfDate, check it's within the grace period (if configured)
        // TODO: enforce_grace_period is currently implemented in a complex manner since
        // dcap-qvl doesn't expose TCB info or TCB date directly in the VerifiedReport. We have to
        // extract the TCB date from the quote and collateral manually, which is not ideal.
        // We should update enforce_grace_period when dcap-qvl adds TCB info to the VerifiedReport.
        // This would remove almost all the tdx/grace_period.rs code.
        enforce_grace_period(
            &report,
            &parsed_quote,
            &collateral,
            self.config.grace_period,
            now_secs,
        )?;

        if !tcb_allowed {
            return Err(AtlsVerificationError::TcbStatusNotAllowed {
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
    ) -> Result<(), AtlsVerificationError> {
        let bootchain = self.config.expected_bootchain.as_ref().ok_or_else(|| {
            AtlsVerificationError::Configuration("expected_bootchain is required".into())
        })?;

        // Get the trusted TD report from DCAP verification
        let td_report = verified_report.report.as_td10().ok_or_else(|| {
            AtlsVerificationError::TeeTypeMismatch(
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
            return Err(AtlsVerificationError::BootchainMismatch {
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
                return Err(AtlsVerificationError::BootchainMismatch {
                    field: format!("rtmr{}", idx),
                    expected: expected_rtmrs[idx].clone(),
                    actual: actual_rtmrs[idx].clone(),
                });
            }
        }

        debug!("Bootchain verification successful");
        Ok(())
    }

    /// Verify RTMR3 against the pinned value using the trusted verified report.
    ///
    /// RTMR3 holds the accumulated runtime events, so pinning it constrains the
    /// whole runtime event sequence rather than the individual events.
    ///
    /// No-op if `expected_rtmr3` is not configured.
    fn verify_rtmr3(&self, verified_report: &VerifiedReport) -> Result<(), AtlsVerificationError> {
        let Some(expected) = self.config.expected_rtmr3.as_ref() else {
            debug!("No expected RTMR3 configured, skipping RTMR3 pinning");
            return Ok(());
        };
        let expected = expected.to_lowercase();

        // Get the trusted TD report from DCAP verification
        let td_report = verified_report.report.as_td10().ok_or_else(|| {
            AtlsVerificationError::TeeTypeMismatch(
                "expected TDX report but got SGX enclave report".into(),
            )
        })?;

        let actual = hex::encode(td_report.rt_mr3);
        debug!("RTMR3 expected: {}", expected);
        debug!("RTMR3 actual:   {}", actual);
        let rtmr3_match = actual == expected;
        debug!("RTMR3 match: {}", rtmr3_match);

        if !rtmr3_match {
            return Err(AtlsVerificationError::BootchainMismatch {
                field: "rtmr3".into(),
                expected,
                actual,
            });
        }

        debug!("RTMR3 verification successful");
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
    ) -> Result<bool, AtlsVerificationError> {
        let cert_hash = hex::encode(Sha256::digest(cert_der));
        debug!("Certificate hash: {}", cert_hash);

        // Find last "New TLS Certificate" event
        let cert_event = events
            .iter()
            .rfind(|e| is_dstack_runtime_event(e, "New TLS Certificate"));

        match cert_event {
            Some(event) => {
                // event_payload is hex-encoded, decode it to get the cert hash string
                let decoded = hex::decode(&event.event_payload).map_err(|e| {
                    AtlsVerificationError::EventLogParse(format!(
                        "failed to hex-decode certificate event payload: {}",
                        e
                    ))
                })?;

                let eventlog_cert_hash = String::from_utf8(decoded).map_err(|e| {
                    AtlsVerificationError::EventLogParse(format!(
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
    fn verify_app_compose(&self, events: &[EventLog]) -> Result<(), AtlsVerificationError> {
        let app_compose = self.config.app_compose.as_ref().ok_or_else(|| {
            AtlsVerificationError::Configuration("app_compose is required".into())
        })?;
        let expected = get_compose_hash(app_compose).map_err(|e| {
            AtlsVerificationError::Configuration(format!(
                "Failed to serialize app_compose for hashing: {}",
                e
            ))
        })?;

        debug!("Verifying app compose hash against trusted event log");
        debug!("App compose hash expected: {}", expected);

        // Verify against event log (trusted after RTMR replay verification)
        let event = events
            .iter()
            .find(|e| is_dstack_runtime_event(e, "compose-hash"))
            .ok_or_else(|| AtlsVerificationError::AppComposeHashMismatch {
                expected: expected.clone(),
                actual: "<not found in event log>".to_string(),
            })?;

        debug!("App compose hash from event log: {}", event.event_payload);
        let eventlog_match = event.event_payload == expected;
        debug!("App compose hash match: {}", eventlog_match);

        if !eventlog_match {
            return Err(AtlsVerificationError::AppComposeHashMismatch {
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
    fn verify_os_image_hash(&self, events: &[EventLog]) -> Result<(), AtlsVerificationError> {
        let expected = self.config.os_image_hash.as_ref().ok_or_else(|| {
            AtlsVerificationError::Configuration("os_image_hash is required".into())
        })?;

        debug!("Verifying OS image hash against trusted event log");
        debug!("OS image hash expected: {}", expected);

        // Verify against event log (trusted after RTMR replay verification)
        let event = events
            .iter()
            .find(|e| is_dstack_runtime_event(e, "os-image-hash"))
            .ok_or_else(|| AtlsVerificationError::OsImageHashMismatch {
                expected: expected.clone(),
                actual: Some("<not found in event log>".to_string()),
            })?;

        debug!("OS image hash from event log: {}", event.event_payload);
        let eventlog_match = &event.event_payload == expected;
        debug!("OS image hash match: {}", eventlog_match);

        if !eventlog_match {
            return Err(AtlsVerificationError::OsImageHashMismatch {
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
    ) -> Result<(), AtlsVerificationError> {
        debug!("Verifying RTMR replay against verified report");

        // Get the trusted TD report from DCAP verification
        let td_report = verified_report.report.as_td10().ok_or_else(|| {
            AtlsVerificationError::TeeTypeMismatch(
                "expected TDX report but got SGX enclave report".into(),
            )
        })?;

        // Use dstack-sdk-types' built-in replay_rtmrs()
        let replayed: BTreeMap<u8, String> = quote_response
            .replay_rtmrs()
            .map_err(AtlsVerificationError::Other)?;

        // Get trusted RTMRs from verified report (as hex strings)
        let trusted_rtmrs = [
            hex::encode(td_report.rt_mr0),
            hex::encode(td_report.rt_mr1),
            hex::encode(td_report.rt_mr2),
            hex::encode(td_report.rt_mr3),
        ];

        for i in 0..4u8 {
            let replayed_rtmr = replayed.get(&i).cloned().ok_or_else(|| {
                AtlsVerificationError::Quote(format!(
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
                return Err(AtlsVerificationError::RtmrMismatch {
                    index: i,
                    expected: trusted_rtmrs[i as usize].clone(),
                    actual: replayed_rtmr,
                });
            }
        }

        debug!("RTMR replay verification successful");
        Ok(())
    }

    /// Verify report data (nonce + session EKM) against the verified report.
    ///
    /// This prevents replay and relay attacks by ensuring the quote was generated specifically
    /// for this verification request, within the current TLS session (identified by EKM).
    fn verify_report_data(
        &self,
        nonce: &[u8; 32],
        session_ekm: &[u8; 32],
        verified_report: &VerifiedReport,
    ) -> Result<(), AtlsVerificationError> {
        debug!("Verifying report data against verified report");

        // Compute report_data = SHA512(nonce || session_ekm)
        let mut hasher = Sha512::new();
        hasher.update(nonce);
        hasher.update(session_ekm);
        let report_data: [u8; 64] = hasher.finalize().into();

        // Get the trusted TD report from DCAP verification
        let td_report = verified_report.report.as_td10().ok_or_else(|| {
            AtlsVerificationError::TeeTypeMismatch(
                "expected TDX report but got SGX enclave report".into(),
            )
        })?;

        let expected = hex::encode(report_data);
        let actual = hex::encode(td_report.report_data);

        debug!("Report data expected: {}", expected);
        debug!("Report data actual:   {}", actual);

        if expected != actual {
            return Err(AtlsVerificationError::ReportDataMismatch { expected, actual });
        }

        debug!("Report data verification successful");
        Ok(())
    }
}

impl AtlsVerifier for DstackTDXVerifier {
    async fn verify<S>(
        &self,
        stream: &mut S,
        peer_cert: &[u8],
        session_ekm: &[u8],
        hostname: &str,
    ) -> Result<Report, AtlsVerificationError>
    where
        S: AsyncByteStream,
    {
        debug!("Starting DStack TDX verification for {}", hostname);

        // 1. Generate nonce and get quote via HTTP POST to /tdx_quote
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);

        // Get quote via HTTP POST to /tdx_quote
        let quote_response = get_quote_over_http(stream, &nonce, hostname).await?;

        // 2. Parse event log using dstack-sdk-types
        debug!("Parsing event log");
        let events = quote_response
            .decode_event_log()
            .map_err(|e| AtlsVerificationError::Other(e.into()))?;
        debug!("Event log parsed, {} events found", events.len());

        // 2b. Authenticate the RTMR3 event payloads against their logged digests.
        // replay_rtmrs() (step 6) trusts each event's `digest` verbatim and never
        // rebinds it to (event_type, event, event_payload); without this, an attacker
        // can keep the genuine digests (so RTMR replay still matches the quote) while
        // rewriting event_payload to forge the cert / compose-hash / os-image-hash that
        // the checks below read. This binds payload -> digest; replay binds digest -> quote.
        verify_event_log_integrity(&events)?;

        // 3. Verify certificate in event log
        debug!("Verifying certificate in event log");
        let cert_in_eventlog = self.verify_cert_in_eventlog(peer_cert, &events)?;
        if !cert_in_eventlog {
            return Err(AtlsVerificationError::CertificateNotInEventLog);
        }

        // 4. Verify DCAP quote using dcap-qvl directly
        debug!("Decoding quote for DCAP verification");
        let quote_bytes = quote_response.decode_quote().map_err(|e| {
            AtlsVerificationError::Other(anyhow::anyhow!("Failed to decode quote: {}", e))
        })?;
        debug!("Quote decoded ({} bytes)", quote_bytes.len());

        // Async quote verification - no blocking!
        let verified_report = self.verify_quote(&quote_bytes).await?;

        // 5. Verify report data
        let session_ekm: &[u8; 32] = session_ekm.try_into().map_err(|_| {
            AtlsVerificationError::Configuration("session_ekm must be exactly 32 bytes".into())
        })?;
        self.verify_report_data(&nonce, session_ekm, &verified_report)?;

        // 6. Verify RTMR replay against the verified report
        self.verify_rtmr_replay(&quote_response, &verified_report)?;

        // Skip remaining checks if runtime verification is disabled
        if self.config.disable_runtime_verification {
            debug!("Runtime verification disabled, skipping bootchain/app-compose/os-image checks");
            return Ok(Report::Tdx(verified_report));
        }

        // 7. Verify bootchain (MRTD, RTMR0-2) against verified report
        self.verify_bootchain(&verified_report)?;

        // 8. Verify pinned RTMR3 against verified report (if configured)
        self.verify_rtmr3(&verified_report)?;

        // 9. Verify app compose hash against trusted event log
        self.verify_app_compose(&events)?;

        // 10. Verify OS image hash against trusted event log
        self.verify_os_image_hash(&events)?;

        debug!("DStack TDX verification complete");
        Ok(Report::Tdx(verified_report))
    }
}

/// Fetch quote over HTTP from /tdx_quote endpoint (async version).
async fn get_quote_over_http<S>(
    stream: &mut S,
    nonce: &[u8; 32],
    hostname: &str,
) -> Result<GetQuoteResponse, AtlsVerificationError>
where
    S: AsyncByteStream,
{
    debug!("Sending POST /tdx_quote request to {}", hostname);

    // Build HTTP POST request for the /tdx_quote endpoint with EKM binding
    let body = serde_json::json!({
        "nonce_hex": hex::encode(nonce)
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
        .map_err(|e| AtlsVerificationError::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| AtlsVerificationError::Io(e.to_string()))?;

    // Read the unauthenticated HTTP response with strict framing and size bounds.
    // The peer controls these bytes until quote verification completes.
    let mut response_buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut expected_response_len = None;

    // Read until we have the complete response
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| AtlsVerificationError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        response_buf.extend_from_slice(&chunk[..n]);

        if expected_response_len.is_none() {
            if let Some(body_start) = find_http_body_start(&response_buf) {
                if body_start > MAX_QUOTE_RESPONSE_HEADER_SIZE {
                    return Err(AtlsVerificationError::Io(format!(
                        "quote response headers exceed {} bytes",
                        MAX_QUOTE_RESPONSE_HEADER_SIZE
                    )));
                }

                let content_length = parse_content_length(&response_buf[..body_start])?;
                if content_length > MAX_QUOTE_RESPONSE_BODY_SIZE {
                    return Err(AtlsVerificationError::Io(format!(
                        "quote response body exceeds {} bytes",
                        MAX_QUOTE_RESPONSE_BODY_SIZE
                    )));
                }

                expected_response_len =
                    Some(body_start.checked_add(content_length).ok_or_else(|| {
                        AtlsVerificationError::Io("quote response length overflow".into())
                    })?);
            } else if response_buf.len() > MAX_QUOTE_RESPONSE_HEADER_SIZE {
                return Err(AtlsVerificationError::Io(format!(
                    "quote response headers exceed {} bytes",
                    MAX_QUOTE_RESPONSE_HEADER_SIZE
                )));
            }
        }

        if expected_response_len.is_some_and(|expected| response_buf.len() >= expected) {
            break;
        }
    }

    debug!("Received quote response ({} bytes)", response_buf.len());

    // Parse HTTP response
    let body_start = find_http_body_start(&response_buf)
        .ok_or_else(|| AtlsVerificationError::Io("Invalid HTTP response".into()))?;
    let content_length = parse_content_length(&response_buf[..body_start])?;
    let expected_response_len = body_start
        .checked_add(content_length)
        .ok_or_else(|| AtlsVerificationError::Io("quote response length overflow".into()))?;
    if response_buf.len() < expected_response_len {
        return Err(AtlsVerificationError::Io(
            "quote response ended before the declared Content-Length".into(),
        ));
    }
    if response_buf.len() > expected_response_len {
        return Err(AtlsVerificationError::Io(
            "quote response contains data beyond the declared Content-Length".into(),
        ));
    }
    let response_body = &response_buf[body_start..expected_response_len];

    let response: QuoteEndpointResponse = serde_json::from_slice(response_body).map_err(|e| {
        AtlsVerificationError::Quote(format!("Failed to parse /tdx_quote response: {}", e))
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

/// Parse the required, unique Content-Length header from an HTTP response.
fn parse_content_length(headers: &[u8]) -> Result<usize, AtlsVerificationError> {
    let headers_str = std::str::from_utf8(headers)
        .map_err(|_| AtlsVerificationError::Io("invalid quote response headers".into()))?;
    let mut content_length = None;

    for line in headers_str.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(AtlsVerificationError::Io(
                "invalid quote response header".into(),
            ));
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(AtlsVerificationError::Io(
                    "duplicate Content-Length in quote response".into(),
                ));
            }
            content_length = Some(value.trim().parse().map_err(|_| {
                AtlsVerificationError::Io("invalid Content-Length in quote response".into())
            })?);
        }
    }

    content_length
        .ok_or_else(|| AtlsVerificationError::Io("quote response is missing Content-Length".into()))
}

/// Authenticate RTMR3 event payloads against their logged digests.
///
/// dstack extends RTMR3 with `digest = sha384(event_type.to_le_bytes() || b":" ||
/// event || b":" || event_payload)`, but `replay_rtmrs()` replays the `digest` field
/// verbatim and never rebinds it to the event contents. atlas reads `event_payload`
/// (cert hash, compose-hash, os-image-hash) to make trust decisions, so a payload that
/// is not tied back to its digest is attacker-controlled. Recomputing the digest closes
/// the chain: payload -> digest here, digest -> quote via `verify_rtmr_replay`.
///
/// IMR 0-2 use the TCG multi-digest format (not this scheme) and are verified
/// against the DCAP report by `verify_bootchain`, never via `event_payload`.
/// IMR >3 is rejected because dstack `replay_rtmrs()` only replays IMR 0-3; accepting
/// higher indexes would let unmeasured entries shadow security-sensitive runtime
/// events.
fn verify_event_log_integrity(events: &[EventLog]) -> Result<(), AtlsVerificationError> {
    for event in events {
        match event.imr {
            0..=2 => continue,
            3 => {}
            other => {
                return Err(AtlsVerificationError::EventLogParse(format!(
                    "unsupported IMR index {} in event log entry '{}'",
                    other, event.event
                )));
            }
        }
        let payload = hex::decode(&event.event_payload).map_err(|e| {
            AtlsVerificationError::EventLogParse(format!(
                "failed to hex-decode event_payload for '{}': {}",
                event.event, e
            ))
        })?;

        let mut hasher = Sha384::new();
        hasher.update(event.event_type.to_le_bytes());
        hasher.update(b":");
        hasher.update(event.event.as_bytes());
        hasher.update(b":");
        hasher.update(&payload);

        if hex::encode(hasher.finalize()) != event.digest {
            return Err(AtlsVerificationError::EventLogDigestMismatch {
                event: event.event.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get_quote_from_response(
        response: Vec<u8>,
    ) -> Result<GetQuoteResponse, AtlsVerificationError> {
        let capacity = response.len().max(1024) + 1024;
        let (mut client, mut server) = tokio::io::duplex(capacity);
        let writer = tokio::spawn(async move {
            server.write_all(&response).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
        let result = get_quote_over_http(&mut client, &nonce, "example.test").await;
        writer.await.unwrap();
        result
    }

    #[tokio::test]
    async fn test_quote_response_valid_content_length_success() {
        let body = br#"{"quote":{"quote":"","event_log":""}}"#;
        let response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        let response = [response, body.to_vec()].concat();

        let quote = get_quote_from_response(response).await.unwrap();

        assert_eq!(quote.quote, "");
        assert_eq!(quote.event_log, "");
    }

    #[tokio::test]
    async fn test_quote_response_oversized_header_failure() {
        let response = [
            b"HTTP/1.1 200 OK\r\nX-Fill: ".as_slice(),
            &vec![b'a'; 64 * 1024],
        ]
        .concat();

        let error = get_quote_from_response(response).await.unwrap_err();

        assert!(error.to_string().contains("quote response headers exceed"));
    }

    #[tokio::test]
    async fn test_quote_response_oversized_body_declaration_failure() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 16777217\r\n\r\n".to_vec();

        let error = get_quote_from_response(response).await.unwrap_err();

        assert!(error.to_string().contains("quote response body exceeds"));
    }

    #[tokio::test]
    async fn test_quote_response_missing_content_length_failure() {
        let response =
            b"HTTP/1.1 200 OK\r\n\r\n{\"quote\":{\"quote\":\"\",\"event_log\":\"\"}}".to_vec();

        let error = get_quote_from_response(response).await.unwrap_err();

        assert!(error.to_string().contains("missing Content-Length"));
    }

    #[tokio::test]
    async fn test_quote_response_duplicate_content_length_failure() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".to_vec();

        let error = get_quote_from_response(response).await.unwrap_err();

        assert!(error.to_string().contains("duplicate Content-Length"));
    }

    #[tokio::test]
    async fn test_quote_response_truncated_body_failure() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort".to_vec();

        let error = get_quote_from_response(response).await.unwrap_err();

        assert!(error.to_string().contains("ended before"));
    }

    fn ev(imr: u32, event_type: u32, event: &str, event_payload: &str, digest: &str) -> EventLog {
        EventLog {
            imr,
            event_type,
            digest: digest.to_string(),
            event: event.to_string(),
            event_payload: event_payload.to_string(),
        }
    }

    /// Real RTMR3 events from a dstack event log (sdk/simulator/eventlog.json), including
    /// an empty-payload event. Proves our recomputation reproduces dstack's actual
    /// `event_digest` output — a non-circular check of the derivation, not just self-consistency.
    #[test]
    fn test_event_log_integrity_genuine_dstack_digests_success() {
        let events = vec![
            ev(
                3,
                DSTACK_RUNTIME_EVENT_TYPE,
                "app-id",
                "ea549f02e1a25fabd1cb788380e033ec5461b2ff",
                "b01c7a2e6a406ae9cd5aa81451e4614e112b8f404df12e6ef506962c1a5279a94dc58da0923c4b7db89e26da9e538302",
            ),
            ev(
                3,
                DSTACK_RUNTIME_EVENT_TYPE,
                "compose-hash",
                "ea549f02e1a25fabd1cb788380e033ec5461b2ffe4328d753642cf035452e48b",
                "9c1fecc259af1e8494484a391bdef460cb74d677c76dd114b1e9e7fac343da4e773b2b0eb8df7a6fc0dd8ba5edbb30e1",
            ),
            ev(
                3,
                DSTACK_RUNTIME_EVENT_TYPE,
                "system-ready",
                "",
                "1a76b2a80a0be71eae59f80945d876351a7a3fb8e9fd1ff1cede5734aa84ea11fd72b4edfbb6f04e5a85edd114c751bd",
            ),
        ];
        assert!(verify_event_log_integrity(&events).is_ok());
    }

    /// Finding A: keep the genuine digest (so RTMR replay still matches the quote) but
    /// rewrite the payload. Must be rejected — otherwise cert/compose/os-image are forgeable
    /// by anyone serving the event log.
    #[test]
    fn test_event_log_integrity_forged_payload_failure() {
        let events = vec![ev(
            3,
            DSTACK_RUNTIME_EVENT_TYPE,
            "compose-hash",
            // attacker-substituted payload, genuine compose-hash digest below
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "9c1fecc259af1e8494484a391bdef460cb74d677c76dd114b1e9e7fac343da4e773b2b0eb8df7a6fc0dd8ba5edbb30e1",
        )];
        assert!(matches!(
            verify_event_log_integrity(&events),
            Err(AtlsVerificationError::EventLogDigestMismatch { .. })
        ));
    }

    /// IMR 0-2 use the TCG multi-digest format, not `event_digest`; dstack `validate()`
    /// skips them and so must we — their payloads are never trusted by atlas.
    #[test]
    fn test_event_log_integrity_ignores_non_rtmr3_success() {
        let events = vec![ev(
            0,
            0x8000_000b,
            "",
            "095464785461626c6500",
            "0e35f1b315ba6c912cf791e5c79dd9d3a2b8704516aa27d4e5aa78fb09ede04aef2bbd02ac7a8734c48562b9c26ba35d",
        )];
        assert!(verify_event_log_integrity(&events).is_ok());
    }

    #[test]
    fn test_event_log_integrity_unknown_imr_failure() {
        for imr in [4, u32::MAX] {
            let events = vec![ev(
                imr,
                DSTACK_RUNTIME_EVENT_TYPE,
                "compose-hash",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "ignored-by-current-replay",
            )];

            assert!(matches!(
                verify_event_log_integrity(&events),
                Err(AtlsVerificationError::EventLogParse(_))
            ));
        }
    }

    #[test]
    fn test_security_events_outside_rtmr3_failure() {
        let app_compose = serde_json::json!({"docker_compose_file": "services: {}"});
        let expected_compose = get_compose_hash(&app_compose).unwrap();
        let expected_os_image = "11".repeat(32);
        let cert = b"unmeasured-certificate";
        let cert_hash = hex::encode(Sha256::digest(cert));
        let events = vec![
            ev(
                0,
                DSTACK_RUNTIME_EVENT_TYPE,
                "compose-hash",
                &expected_compose,
                "unused",
            ),
            ev(
                1,
                DSTACK_RUNTIME_EVENT_TYPE,
                "os-image-hash",
                &expected_os_image,
                "unused",
            ),
            ev(
                2,
                DSTACK_RUNTIME_EVENT_TYPE,
                "New TLS Certificate",
                &hex::encode(cert_hash.as_bytes()),
                "unused",
            ),
            ev(3, 0x0800_0002, "compose-hash", &expected_compose, "unused"),
            ev(
                3,
                0x0800_0002,
                "os-image-hash",
                &expected_os_image,
                "unused",
            ),
            ev(
                3,
                0x0800_0002,
                "New TLS Certificate",
                &hex::encode(cert_hash.as_bytes()),
                "unused",
            ),
        ];
        let verifier = DstackTDXVerifier::new(DstackTDXVerifierConfig {
            app_compose: Some(app_compose),
            os_image_hash: Some(expected_os_image),
            disable_runtime_verification: true,
            ..Default::default()
        })
        .unwrap();

        assert!(!verifier.verify_cert_in_eventlog(cert, &events).unwrap());
        assert!(verifier.verify_app_compose(&events).is_err());
        assert!(verifier.verify_os_image_hash(&events).is_err());
    }

    #[test]
    fn test_security_events_in_rtmr3_success() {
        let app_compose = serde_json::json!({"docker_compose_file": "services: {}"});
        let expected_compose = get_compose_hash(&app_compose).unwrap();
        let expected_os_image = "11".repeat(32);
        let cert = b"measured-certificate";
        let cert_hash = hex::encode(Sha256::digest(cert));
        let events = vec![
            ev(
                3,
                DSTACK_RUNTIME_EVENT_TYPE,
                "compose-hash",
                &expected_compose,
                "unused",
            ),
            ev(
                3,
                DSTACK_RUNTIME_EVENT_TYPE,
                "os-image-hash",
                &expected_os_image,
                "unused",
            ),
            ev(
                3,
                DSTACK_RUNTIME_EVENT_TYPE,
                "New TLS Certificate",
                &hex::encode(cert_hash.as_bytes()),
                "unused",
            ),
        ];
        let verifier = DstackTDXVerifier::new(DstackTDXVerifierConfig {
            app_compose: Some(app_compose),
            os_image_hash: Some(expected_os_image),
            disable_runtime_verification: true,
            ..Default::default()
        })
        .unwrap();

        assert!(verifier.verify_cert_in_eventlog(cert, &events).unwrap());
        assert!(verifier.verify_app_compose(&events).is_ok());
        assert!(verifier.verify_os_image_hash(&events).is_ok());
    }

    /// Pinned RTMR3 used by the tests (48 bytes = 96 hex chars, SHA384-sized).
    const TEST_RTMR3: &str = "1f2e3d4c5b6a79880716253443526170a1b2c3d4e5f60718293a4b5c6d7e8f900a1b2c3d4e5f60718293a4b5c6d7e8f9";
    /// A different, equally well-formed RTMR3 the TD did not report.
    const OTHER_RTMR3: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn rtmr3_bytes(hex_str: &str) -> [u8; 48] {
        hex::decode(hex_str)
            .expect("test RTMR3 must be hex")
            .try_into()
            .expect("test RTMR3 must be 48 bytes")
    }

    /// Build a synthetic DCAP-verified report carrying the given RTMR3.
    ///
    /// `VerifiedReport` has no public constructor, so it is deserialized from
    /// its own serde representation.
    fn verified_report_with_rtmr3(rt_mr3: [u8; 48]) -> VerifiedReport {
        use dcap_qvl::quote::TDReport10;
        let td_report = TDReport10 {
            tee_tcb_svn: [0u8; 16],
            mr_seam: [0u8; 48],
            mr_signer_seam: [0u8; 48],
            seam_attributes: [0u8; 8],
            td_attributes: [0u8; 8],
            xfam: [0u8; 8],
            mr_td: [0u8; 48],
            mr_config_id: [0u8; 48],
            mr_owner: [0u8; 48],
            mr_owner_config: [0u8; 48],
            rt_mr0: [0u8; 48],
            rt_mr1: [0u8; 48],
            rt_mr2: [0u8; 48],
            rt_mr3,
            report_data: [0u8; 64],
        };
        let tcb_status = serde_json::json!({ "status": "UpToDate", "advisory_ids": [] });
        serde_json::from_value(serde_json::json!({
            "status": "UpToDate",
            "advisory_ids": [],
            "report": { "TD10": td_report },
            "ppid": "",
            "qe_status": tcb_status,
            "platform_status": tcb_status,
        }))
        .expect("synthetic VerifiedReport should deserialize")
    }

    /// Verifier exercising `verify_rtmr3` in isolation; the other runtime
    /// checks are switched off so the config passes `new()` without them.
    fn verifier_with_expected_rtmr3(expected: Option<&str>) -> DstackTDXVerifier {
        DstackTDXVerifier::new(DstackTDXVerifierConfig {
            expected_rtmr3: expected.map(str::to_string),
            disable_runtime_verification: true,
            ..Default::default()
        })
        .expect("verifier should build")
    }

    #[test]
    fn test_verify_rtmr3_matching_pin_accepted() {
        let verifier = verifier_with_expected_rtmr3(Some(TEST_RTMR3));
        let report = verified_report_with_rtmr3(rtmr3_bytes(TEST_RTMR3));

        assert!(verifier.verify_rtmr3(&report).is_ok());
    }

    #[test]
    fn test_verify_rtmr3_uppercase_pin_accepted() {
        // Expected values are normalized before comparison, so a pin supplied
        // through the builder (which bypasses policy validation) still matches.
        let verifier = verifier_with_expected_rtmr3(Some(&TEST_RTMR3.to_uppercase()));
        let report = verified_report_with_rtmr3(rtmr3_bytes(TEST_RTMR3));

        assert!(verifier.verify_rtmr3(&report).is_ok());
    }

    #[test]
    fn test_verify_rtmr3_mismatch_rejected() {
        let verifier = verifier_with_expected_rtmr3(Some(TEST_RTMR3));
        let report = verified_report_with_rtmr3(rtmr3_bytes(OTHER_RTMR3));

        let err = verifier
            .verify_rtmr3(&report)
            .expect_err("mismatched RTMR3 must fail the connection");

        match err {
            AtlsVerificationError::BootchainMismatch {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "rtmr3");
                assert_eq!(expected, TEST_RTMR3);
                assert_eq!(actual, OTHER_RTMR3);
            }
            other => panic!("expected BootchainMismatch, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_rtmr3_absent_pin_skips_check() {
        // Backward compatibility: policies without expected_rtmr3 accept any RTMR3.
        let verifier = verifier_with_expected_rtmr3(None);
        let report = verified_report_with_rtmr3(rtmr3_bytes(OTHER_RTMR3));

        assert!(verifier.verify_rtmr3(&report).is_ok());
    }
}
