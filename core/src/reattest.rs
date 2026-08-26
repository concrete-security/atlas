//! Client-side re-attestation of established aTLS connections.
//!
//! [`Reattester`] retains everything needed to re-verify a connection after
//! [`atls_connect_with_reattester`](crate::atls_connect_with_reattester)
//! returns: the verifier (with its policy), the session peer certificate,
//! the session EKM, and the time of the last successful verification.
//!
//! Re-attestation repeats the full verification pipeline with a fresh nonce
//! bound to the same session EKM (`report_data = SHA512(nonce || ekm)`), so
//! each cycle carries the same security weight as the initial attestation.
//! The session EKM never leaves the TLS endpoints, so reusing it across
//! rounds is sound — it is exactly what binds the fresh evidence to *this*
//! live session (RFC 9266 channel binding).
//!
//! There are no background timers: callers check [`Reattester::is_due`] at
//! safe message boundaries (no request/response in flight) and re-attest
//! lazily. The configured interval is therefore the maximum age of the
//! attestation evidence at the moment the connection is used.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::AtlsVerificationError;
use crate::time::mono_millis;
use crate::verifier::{AsyncByteStream, Report, Verifier};

/// Whether evidence of `age_secs` is due for re-attestation.
///
/// An interval of 0 disables re-attestation entirely.
fn due(age_secs: u64, interval_secs: u64) -> bool {
    interval_secs != 0 && age_secs >= interval_secs
}

/// Evidence age in seconds from monotonic-clock readings.
///
/// If the clock appears to have moved backwards (possible only with the wasm
/// `Date.now()` fallback; the native `Instant` source is monotonic), the
/// evidence is treated as maximally stale so re-attestation triggers
/// (fail closed) rather than the age silently reading as zero.
fn age_secs(now_millis: u64, verified_at_millis: u64) -> u64 {
    if now_millis < verified_at_millis {
        return u64::MAX;
    }
    (now_millis - verified_at_millis) / 1000
}

/// Re-attestation handle for an established aTLS connection.
///
/// Obtained from [`atls_connect_with_reattester`](crate::atls_connect_with_reattester).
/// All methods take `&self`; the handle can be shared (e.g. behind an `Arc`)
/// between the connection owner and whatever schedules re-attestation.
///
/// # Safe usage
///
/// [`reattest`](Self::reattest) writes a `POST /tdx_quote` request on the
/// live stream and reads its response. The caller must guarantee the
/// connection is quiescent (no application request or response in flight),
/// otherwise the exchange would interleave with application traffic.
///
/// On failure the error is wrapped in
/// [`AtlsVerificationError::Reattestation`] and the evidence age is *not*
/// refreshed: treat the connection as unverified and stop using it
/// (fail closed).
//
// NOTE: deliberately no `Debug` impl — the struct holds the session EKM,
// which must never be logged.
pub struct Reattester {
    verifier: Verifier,
    peer_cert: Vec<u8>,
    session_ekm: Vec<u8>,
    server_name: String,
    interval_secs: u64,
    /// Monotonic-clock milliseconds ([`mono_millis`]) of the last successful
    /// verification, so wall-clock steps cannot shrink the evidence age.
    verified_at_millis: AtomicU64,
}

impl Reattester {
    /// Create a handle for a session that was verified just now.
    ///
    /// The interval is read from the verifier's policy
    /// (`reattestation_interval_secs`; 0 disables re-attestation).
    ///
    /// Public for custom integrations that perform the handshake and initial
    /// verification manually (via [`tls_handshake`](crate::connect::tls_handshake)
    /// and [`AtlsVerifier::verify`](crate::AtlsVerifier::verify)); prefer
    /// [`atls_connect_with_reattester`](crate::atls_connect_with_reattester),
    /// which constructs the handle with the exact session material.
    pub fn new(
        verifier: Verifier,
        peer_cert: Vec<u8>,
        session_ekm: Vec<u8>,
        server_name: String,
    ) -> Self {
        let now = mono_millis();
        Self::new_at(verifier, peer_cert, session_ekm, server_name, now)
    }

    /// Create a handle anchored at `verified_at_millis` — the moment the
    /// initial verification *started* (nonce issuance), not when it
    /// completed, so a slow exchange cannot overstate freshness.
    pub(crate) fn new_at(
        verifier: Verifier,
        peer_cert: Vec<u8>,
        session_ekm: Vec<u8>,
        server_name: String,
        verified_at_millis: u64,
    ) -> Self {
        let interval_secs = verifier.reattestation_interval_secs();
        Self {
            verifier,
            peer_cert,
            session_ekm,
            server_name,
            interval_secs,
            verified_at_millis: AtomicU64::new(verified_at_millis),
        }
    }

    /// The server name the connection was verified against.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Configured re-attestation interval in seconds (0 = disabled).
    pub fn interval_secs(&self) -> u64 {
        self.interval_secs
    }

    /// Age in seconds of the current attestation evidence, measured on a
    /// monotonic clock. Reads as maximally stale if the clock ever appears
    /// to move backwards (wasm `Date.now()` fallback only).
    pub fn evidence_age_secs(&self) -> u64 {
        age_secs(
            mono_millis(),
            self.verified_at_millis.load(Ordering::Acquire),
        )
    }

    /// Whether the attestation evidence is older than the configured
    /// interval and the connection should be re-attested before further use.
    ///
    /// Always `false` when re-attestation is disabled (interval 0).
    pub fn is_due(&self) -> bool {
        due(self.evidence_age_secs(), self.interval_secs)
    }

    /// Re-attest the connection in-band over `stream`.
    ///
    /// Sends a `POST /tdx_quote` request with a fresh nonce on the live
    /// stream and runs the full verification pipeline on the response. The
    /// stream must be quiescent (see the type-level docs). On success the
    /// evidence age is anchored at the moment the exchange *started* (so a
    /// slow exchange cannot overstate freshness); on failure it does not
    /// change and the connection must not be used further.
    pub async fn reattest<S>(&self, stream: &mut S) -> Result<Report, AtlsVerificationError>
    where
        S: AsyncByteStream,
    {
        let issued_at_millis = mono_millis();
        let result = self
            .verifier
            .reverify(
                stream,
                &self.peer_cert,
                &self.session_ekm,
                &self.server_name,
            )
            .await;
        self.finish_result(result, issued_at_millis)
    }

    /// Begin a re-attestation exchange over a caller-owned transport.
    ///
    /// Use this when the raw stream is not directly accessible (e.g. it is
    /// owned by an HTTP client): send an HTTP request built from the
    /// returned [`ReattestRequest`] to the attester, then pass the response
    /// body to [`finish`](Self::finish). The request records its issuance
    /// time; on success the evidence age is anchored there.
    pub fn begin(&self) -> ReattestRequest {
        ReattestRequest {
            nonce: rand::random(),
            issued_at_millis: mono_millis(),
        }
    }

    /// Finish a re-attestation exchange started with [`begin`](Self::begin).
    ///
    /// `response_body` is the raw body of the `/tdx_quote` HTTP response.
    /// Runs the full verification pipeline; the response must prove
    /// `report_data == SHA512(nonce || session_ekm)` for the nonce issued by
    /// `begin`. Same success/failure semantics as [`reattest`](Self::reattest).
    ///
    /// Consumes the request: a completed exchange cannot be replayed to
    /// refresh the evidence age again, and the age is anchored at the
    /// request's issuance time — a delayed or out-of-order completion can
    /// never make evidence look fresher than a newer one already recorded.
    pub async fn finish(
        &self,
        request: ReattestRequest,
        response_body: &[u8],
    ) -> Result<Report, AtlsVerificationError> {
        let result = self
            .verifier
            .appraise_quote_body(
                response_body,
                &request.nonce,
                &self.peer_cert,
                &self.session_ekm,
            )
            .await;
        self.finish_result(result, request.issued_at_millis)
    }

    /// Record success (anchor evidence age at issuance) or wrap failure.
    fn finish_result(
        &self,
        result: Result<Report, AtlsVerificationError>,
        issued_at_millis: u64,
    ) -> Result<Report, AtlsVerificationError> {
        match result {
            Ok(report) => {
                self.record_verified_at(issued_at_millis);
                Ok(report)
            }
            Err(source) => Err(AtlsVerificationError::Reattestation {
                source: Box::new(source),
            }),
        }
    }

    /// Advance the last-verified time to `issued_at_millis`, never backwards:
    /// an older exchange completing late must not shadow a newer success.
    fn record_verified_at(&self, issued_at_millis: u64) {
        self.verified_at_millis
            .fetch_max(issued_at_millis, Ordering::AcqRel);
    }
}

/// A prepared re-attestation request for caller-owned transports.
///
/// Holds the fresh nonce (kept private so it cannot be tampered with between
/// [`Reattester::begin`] and [`Reattester::finish`]) and its issuance time,
/// plus helpers describing the HTTP request to send to the attester.
///
/// Deliberately neither `Clone` nor `Copy`: [`Reattester::finish`] consumes
/// it, so one issued nonce can complete at most one exchange.
pub struct ReattestRequest {
    nonce: [u8; 32],
    issued_at_millis: u64,
}

impl ReattestRequest {
    /// HTTP method of the quote endpoint.
    pub fn method() -> &'static str {
        "POST"
    }

    /// Path of the quote endpoint.
    pub fn path() -> &'static str {
        "/tdx_quote"
    }

    /// Content type of the request body.
    pub fn content_type() -> &'static str {
        "application/json"
    }

    /// JSON request body carrying the nonce.
    pub fn body_json(&self) -> String {
        serde_json::json!({ "nonce_hex": hex::encode(self.nonce) }).to_string()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::dstack::DstackTdxPolicy;
    use crate::policy::Policy;
    use crate::verifier::IntoVerifier;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn test_reattester(interval_secs: u64) -> Reattester {
        let mut policy = DstackTdxPolicy::dev();
        policy.reattestation_interval_secs = interval_secs;
        let verifier = Policy::DstackTdx(policy).into_verifier().unwrap();
        Reattester::new(
            verifier,
            b"peer-cert-der".to_vec(),
            vec![0u8; 32],
            "tee.test".to_string(),
        )
    }

    fn backdate(reattester: &Reattester, secs: u64) {
        reattester
            .verified_at_millis
            .store(mono_millis().saturating_sub(secs * 1000), Ordering::Release);
    }

    /// Read one HTTP request (headers + Content-Length body) from the stream.
    async fn read_http_request(server: &mut DuplexStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = server.read(&mut chunk).await.unwrap();
            assert!(n > 0, "client closed while sending request");
            buf.extend_from_slice(&chunk[..n]);

            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if buf.len() >= pos + 4 + content_length {
                    return String::from_utf8(buf).unwrap();
                }
            }
        }
    }

    fn quote_response_with_empty_event_log() -> String {
        let body = serde_json::json!({
            "quote": {
                "quote": "",
                "event_log": "[]",
                "report_data": "",
                "vm_config": ""
            }
        })
        .to_string();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    }

    fn extract_nonce_hex(request: &str) -> String {
        let body = request.split("\r\n\r\n").nth(1).unwrap();
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        json["nonce_hex"].as_str().unwrap().to_string()
    }

    #[test]
    fn test_due_math() {
        // 0 disables re-attestation regardless of age.
        assert!(!due(0, 0));
        assert!(!due(10_000, 0));
        // Age thresholds.
        assert!(!due(299, 300));
        assert!(due(300, 300));
        assert!(due(301, 300));
    }

    #[test]
    fn test_age_secs_clock_rollback_is_maximally_stale() {
        // An apparent backwards clock step (possible only with the wasm
        // Date.now() fallback) must read as stale, never as fresh.
        assert_eq!(age_secs(1_000, 2_000), u64::MAX);
        assert!(due(age_secs(1_000, 2_000), 300));
        // Disabled re-attestation stays disabled even on rollback.
        assert!(!due(age_secs(1_000, 2_000), 0));
        // Normal forward progression.
        assert_eq!(age_secs(301_000, 1_000), 300);
        assert_eq!(age_secs(1_000, 1_000), 0);
    }

    #[test]
    fn test_is_due_after_clock_rollback() {
        let reattester = test_reattester(300);
        // Simulate a verification stamped "in the future" relative to the
        // current monotonic reading (i.e. the clock rolled back).
        reattester
            .verified_at_millis
            .store(mono_millis() + 3_600_000, Ordering::Release);
        assert!(reattester.is_due(), "rollback must fail closed");

        let disabled = test_reattester(0);
        disabled
            .verified_at_millis
            .store(mono_millis() + 3_600_000, Ordering::Release);
        assert!(!disabled.is_due(), "interval 0 stays disabled on rollback");
    }

    #[test]
    fn test_is_due_lifecycle() {
        let reattester = test_reattester(300);
        assert!(!reattester.is_due(), "fresh evidence must not be due");
        assert!(reattester.evidence_age_secs() <= 1);

        backdate(&reattester, 400);
        assert!(reattester.evidence_age_secs() >= 400);
        assert!(reattester.is_due());

        let disabled = test_reattester(0);
        backdate(&disabled, 1_000_000);
        assert!(!disabled.is_due(), "interval 0 must disable re-attestation");
        assert_eq!(disabled.interval_secs(), 0);
    }

    #[test]
    fn test_reattest_request_body_shape() {
        let reattester = test_reattester(300);
        let req1 = reattester.begin();
        let req2 = reattester.begin();

        let json: serde_json::Value = serde_json::from_str(&req1.body_json()).unwrap();
        let nonce_hex = json["nonce_hex"].as_str().unwrap();
        assert_eq!(nonce_hex.len(), 64);
        assert!(nonce_hex.chars().all(|c| c.is_ascii_hexdigit()));

        // Fresh nonce for every exchange.
        assert_ne!(req1.body_json(), req2.body_json());

        assert_eq!(ReattestRequest::method(), "POST");
        assert_eq!(ReattestRequest::path(), "/tdx_quote");
        assert_eq!(ReattestRequest::content_type(), "application/json");
    }

    #[tokio::test]
    async fn test_reattest_request_framing_and_fail_closed_appraisal() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let reattester = test_reattester(300);

        let server_task = tokio::spawn(async move {
            let request = read_http_request(&mut server).await;
            assert!(request.starts_with("POST /tdx_quote HTTP/1.1\r\n"));
            assert!(request.contains("Host: tee.test\r\n"));
            assert!(request.contains("Content-Type: application/json\r\n"));
            let nonce_hex = extract_nonce_hex(&request);
            assert_eq!(nonce_hex.len(), 64);

            // Valid HTTP but an empty event log: appraisal must fail closed
            // at the certificate check, before any network access. Deliver
            // the response across many partial writes to exercise the
            // client's read loop.
            let response = quote_response_with_empty_event_log();
            for chunk in response.as_bytes().chunks(17) {
                server.write_all(chunk).await.unwrap();
                server.flush().await.unwrap();
            }
            nonce_hex
        });

        let err = reattester.reattest(&mut client).await.unwrap_err();
        match err {
            AtlsVerificationError::Reattestation { source } => {
                assert!(matches!(
                    *source,
                    AtlsVerificationError::CertificateNotInEventLog
                ));
            }
            other => panic!("expected Reattestation error, got: {other}"),
        }
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_reattest_uses_fresh_nonce_per_exchange() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let reattester = test_reattester(300);

        let server_task = tokio::spawn(async move {
            let mut nonces = Vec::new();
            for _ in 0..2 {
                let request = read_http_request(&mut server).await;
                nonces.push(extract_nonce_hex(&request));
                let response = quote_response_with_empty_event_log();
                server.write_all(response.as_bytes()).await.unwrap();
                server.flush().await.unwrap();
            }
            nonces
        });

        // Both exchanges fail appraisal (empty event log); we only care that
        // each one sent a distinct nonce.
        let _ = reattester.reattest(&mut client).await.unwrap_err();
        let _ = reattester.reattest(&mut client).await.unwrap_err();

        let nonces = server_task.await.unwrap();
        assert_eq!(nonces.len(), 2);
        assert_ne!(nonces[0], nonces[1], "nonce must be fresh per exchange");
    }

    #[tokio::test]
    async fn test_reattest_failure_keeps_evidence_stale() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let reattester = test_reattester(300);
        backdate(&reattester, 400);
        assert!(reattester.is_due());

        let server_task = tokio::spawn(async move {
            let _request = read_http_request(&mut server).await;
            // Close without responding: the client sees EOF mid-exchange.
            drop(server);
        });

        let err = reattester.reattest(&mut client).await.unwrap_err();
        match err {
            AtlsVerificationError::Reattestation { source } => {
                assert!(matches!(*source, AtlsVerificationError::Io(_)));
            }
            other => panic!("expected Reattestation error, got: {other}"),
        }
        assert!(
            reattester.is_due(),
            "failed re-attestation must not refresh the evidence age"
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_finish_rejects_invalid_response_body() {
        let reattester = test_reattester(300);
        let request = reattester.begin();

        let err = reattester.finish(request, b"not json").await.unwrap_err();
        match err {
            AtlsVerificationError::Reattestation { source } => {
                assert!(matches!(*source, AtlsVerificationError::Quote(_)));
            }
            other => panic!("expected Reattestation error, got: {other}"),
        }
    }

    #[test]
    fn test_begin_stamps_issuance_time() {
        let reattester = test_reattester(300);
        let before = mono_millis();
        let request = reattester.begin();
        let after = mono_millis();
        assert!(request.issued_at_millis >= before);
        assert!(request.issued_at_millis <= after);
    }

    #[test]
    fn test_record_verified_at_never_regresses() {
        let reattester = test_reattester(300);
        let newer = mono_millis() + 10_000;
        let older = newer - 5_000;

        // A newer exchange completes first...
        reattester.record_verified_at(newer);
        // ...then an older-issued exchange completes late: it must not make
        // the evidence look fresher than the newer success, nor roll it back.
        reattester.record_verified_at(older);

        assert_eq!(
            reattester.verified_at_millis.load(Ordering::Acquire),
            newer,
            "out-of-order completion must not shadow a newer success"
        );
    }

    #[tokio::test]
    async fn test_delayed_failed_completion_keeps_evidence_stale() {
        let reattester = test_reattester(300);
        backdate(&reattester, 400);
        assert!(reattester.is_due());

        // A request issued long ago (delayed completion) that fails appraisal
        // must not refresh anything.
        let stale_request = ReattestRequest {
            nonce: [0u8; 32],
            issued_at_millis: mono_millis().saturating_sub(1_000_000),
        };
        let err = reattester
            .finish(stale_request, b"not json")
            .await
            .unwrap_err();
        assert!(matches!(err, AtlsVerificationError::Reattestation { .. }));
        assert!(reattester.is_due(), "failed completion must keep staleness");
        // Note: replaying a completed exchange is prevented at compile time —
        // `finish` consumes the `ReattestRequest`, which is neither Clone nor
        // Copy.
    }
}
