use crate::{platform::SystemTime, AttestationResult, Policy, RatlsError, TeeType};
use dcap_qvl::quote::{Quote, Report, TDReport10, TDReport15};
use dcap_qvl::QuoteCollateralV3;
use hex::{decode, encode};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TdxTcbPolicy {
    #[serde(
        default,
        serialize_with = "serialize_hex_opt",
        deserialize_with = "deserialize_hex_opt"
    )]
    pub mrseam: Option<Vec<u8>>,
    #[serde(
        default,
        serialize_with = "serialize_hex_opt",
        deserialize_with = "deserialize_hex_opt"
    )]
    pub mrtmrs: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcgEvent {
    #[serde(alias = "event_type", alias = "type")]
    pub event_type: u32,
    #[serde(alias = "event")]
    pub event: String,
    #[serde(alias = "event_payload")]
    pub event_payload: String,
    pub digest: String,
    pub imr: u32,
}

pub async fn verify_attestation(
    quote: &[u8],
    collateral: &QuoteCollateralV3,
    policy: &Policy,
) -> Result<AttestationResult, RatlsError> {
    if policy.tee_type != TeeType::Tdx {
        return Err(RatlsError::TeeUnsupported(
            "only TDX attestation supported".into(),
        ));
    }

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| RatlsError::Policy(e.to_string()))?
        .as_secs();
    let verified = dcap_qvl::verify::verify(quote, collateral, now)
        .map_err(|e| RatlsError::Vendor(format!("tdx verify failed: {e}")))?;
    let status = verified.status.clone();
    if !policy
        .allowed_tdx_status
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&status))
    {
        return Err(RatlsError::Policy(format!(
            "tdx status {status} not allowed"
        )));
    }

    let report = TdReportRef::from_report(&verified.report)?;

    if let Some(tcb_policy) = &policy.min_tdx_tcb {
        enforce_tcb_policy(report.as_td10(), tcb_policy)?;
    }

    let measurement = encode(report.as_td10().mr_td);

    Ok(AttestationResult {
        trusted: true,
        tee_type: TeeType::Tdx,
        measurement: Some(measurement),
        tcb_status: status,
        advisory_ids: verified.advisory_ids,
    })
}

pub fn verify_quote_freshness(quote: &[u8], report_data_expected: &[u8]) -> Result<(), RatlsError> {
    let parsed = parse_quote_report(quote)?;
    let report = TdReportRef::from_report(&parsed.report)?;
    let report_data = report.report_data();
    if report_data_expected.len() > report_data.len() {
        return Err(RatlsError::Policy(
            "nonce is larger than report data field".into(),
        ));
    }
    if report_data[..report_data_expected.len()] != report_data_expected[..] {
        let expected = hex::encode(&report_data_expected[..report_data_expected.len().min(16)]);
        let actual = hex::encode(&report_data[..report_data_expected.len().min(16)]);
        return Err(RatlsError::Policy(format!(
            "report data mismatch (nonce binding): expected prefix {expected}, quote prefix {actual}"
        )));
    }
    Ok(())
}

pub fn verify_event_log_integrity(quote: &[u8], events: &[TcgEvent]) -> Result<(), RatlsError> {
    if events.is_empty() {
        return Err(RatlsError::Policy(
            "event log missing from attestation response".into(),
        ));
    }

    let parsed = parse_quote_report(quote)?;
    let report = TdReportRef::from_report(&parsed.report)?;
    let mut accumulators = [[0u8; 48]; 4];
    let mut last_events: [Option<(String, String)>; 4] = std::array::from_fn(|_| None);
    let mut processed = [0usize; 4];

    for event in events {
        if event.imr > 3 {
            return Err(RatlsError::Vendor(format!(
                "event '{}' references unsupported RTMR{}",
                event.label(),
                event.imr
            )));
        }
        let idx = event.imr as usize;
        let mut digest = event.digest_bytes()?;
        if digest.len() < accumulators[idx].len() {
            digest.resize(accumulators[idx].len(), 0);
        }
        if digest.len() != accumulators[idx].len() {
            return Err(RatlsError::Vendor(format!(
                "event '{}' digest has invalid length {}",
                event.label(),
                digest.len()
            )));
        }

        let mut hasher = Sha384::new();
        hasher.update(&accumulators[idx]);
        hasher.update(&digest);
        let hashed = hasher.finalize();
        accumulators[idx].copy_from_slice(&hashed);
        processed[idx] += 1;
        last_events[idx] = Some((event.label(), hex::encode(&digest)));
    }

    let td10 = report.as_td10();
    let expected = [
        td10.rt_mr0.clone(),
        td10.rt_mr1.clone(),
        td10.rt_mr2.clone(),
        td10.rt_mr3.clone(),
    ];

    for (idx, expected_reg) in expected.into_iter().enumerate() {
        if accumulators[idx] != expected_reg {
            let (last_msg, last_digest) = last_events[idx]
                .clone()
                .unwrap_or_else(|| ("none".into(), "n/a".into()));
            return Err(RatlsError::Policy(format!(
                "event log replay mismatch for RTMR{idx} (expected {}, computed {}, events_processed {}, last_event '{}' digest {})",
                hex::encode(expected_reg),
                hex::encode(accumulators[idx]),
                processed[idx],
                last_msg,
                last_digest
            )));
        }
    }

    Ok(())
}

pub fn verify_tls_certificate_in_log(
    events: &[TcgEvent],
    cert_data: &[u8],
) -> Result<(), RatlsError> {
    let mut hasher = Sha256::new();
    hasher.update(cert_data);
    let cert_hash = encode(hasher.finalize());

    let mut last_payload = None;
    for event in events {
        if event.event.as_str().eq_ignore_ascii_case("New TLS Certificate") {
            last_payload = event.payload_as_string();
        }
    }

    if let Some(payload) = last_payload {
        if payload == cert_hash {
            return Ok(());
        }
    }

    Err(RatlsError::Policy(
        "TLS public key hash missing from event log".into(),
    ))
}

impl TcgEvent {
    fn digest_bytes(&self) -> Result<Vec<u8>, RatlsError> {
        decode_hex_field(&self.digest)
            .map_err(|e| RatlsError::Vendor(format!("invalid digest for event '{}': {e}", self.label())))
    }

    fn payload_as_string(&self) -> Option<String> {
        let raw = self.event_payload.trim();
        if raw.is_empty() {
            return None;
        }
        let bytes = decode_hex_field(raw).ok()?;
        String::from_utf8(bytes).ok()
    }

    fn label(&self) -> String {
        let trimmed = self.event.trim();
        if trimmed.is_empty() {
            format!("type {}", self.event_type)
        } else {
            trimmed.to_string()
        }
    }
}

fn enforce_tcb_policy(report: &TDReport10, policy: &TdxTcbPolicy) -> Result<(), RatlsError> {
    if let Some(expected) = &policy.mrseam {
        if report.mr_seam[..expected.len()] != expected[..] {
            return Err(RatlsError::Policy("mr_seam mismatch".into()));
        }
    }
    if let Some(expected) = &policy.mrtmrs {
        if report.rt_mr0[..expected.len()] != expected[..] {
            return Err(RatlsError::Policy("rt_mr0 mismatch".into()));
        }
    }
    Ok(())
}

enum TdReportRef<'a> {
    Td10(&'a TDReport10),
    Td15(&'a TDReport15),
}

impl<'a> TdReportRef<'a> {
    fn from_report(report: &'a Report) -> Result<Self, RatlsError> {
        match report {
            Report::TD10(r) => Ok(TdReportRef::Td10(r)),
            Report::TD15(r) => Ok(TdReportRef::Td15(r)),
            other => Err(RatlsError::TeeUnsupported(format!(
                "unsupported report type: {other:?}"
            ))),
        }
    }

    fn as_td10(&self) -> &TDReport10 {
        match self {
            TdReportRef::Td10(r) => r,
            TdReportRef::Td15(r) => &r.base,
        }
    }

    fn report_data(&self) -> &[u8; 64] {
        match self {
            TdReportRef::Td10(r) => &r.report_data,
            TdReportRef::Td15(r) => &r.base.report_data,
        }
    }
}

fn parse_quote_report(quote: &[u8]) -> Result<Quote, RatlsError> {
    Quote::parse(quote).map_err(|e| RatlsError::Vendor(format!("failed to parse quote: {e}")))
}

fn decode_hex_field(value: &str) -> Result<Vec<u8>, String> {
    let normalized = normalize_hex(value);
    decode(&normalized).map_err(|e| format!("invalid hex '{value}': {e}"))
}

fn normalize_hex(value: &str) -> String {
    let mut lowered = value.trim().to_ascii_lowercase();
    if lowered.starts_with("0x") {
        lowered.drain(..2);
    }
    lowered.retain(|ch| !ch.is_ascii_whitespace());
    lowered
}

fn serialize_hex_opt<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(bytes) => serializer.serialize_some(&encode(bytes)),
        None => serializer.serialize_none(),
    }
}

fn deserialize_hex_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    opt.map(|s| {
        let normalized = normalize_hex(&s);
        decode(&normalized).map_err(DeError::custom)
    })
    .transpose()
}

pub fn parse_event_log(value: Value) -> Result<Vec<TcgEvent>, RatlsError> {
    match value {
        Value::Null => Ok(vec![]),
        Value::Array(_) => serde_json::from_value(value)
            .map_err(|e| RatlsError::Vendor(format!("Invalid event log array: {e}"))),
        Value::String(s) => {
            if s.trim().is_empty() {
                Ok(vec![])
            } else {
                let preview = event_log_preview(&s);
                serde_json::from_str::<Vec<TcgEvent>>(&s).map_err(|e| {
                    RatlsError::Vendor(format!(
                        "Invalid event log string (len {}, preview {}): {e}",
                        s.len(),
                        preview
                    ))
                })
            }
        }
        other => Err(RatlsError::Vendor(format!(
            "Unsupported event log format: {other}"
        ))),
    }
}

fn event_log_preview(s: &str) -> String {
    let trimmed = s.trim();
    let mut snippet: String = trimmed.chars().take(120).collect();
    if trimmed.len() > snippet.len() {
        snippet.push('…');
    }
    snippet.replace('\n', "\\n")
}
