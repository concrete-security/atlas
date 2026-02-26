//! Grace period checks for TDX TCB status.

use chrono::DateTime;
use dcap_qvl::intel::parse_pck_extension;
use dcap_qvl::quote::Quote;
use dcap_qvl::QuoteCollateralV3;
use dcap_qvl::verify::VerifiedReport;
use pem::parse_many;
use serde::Deserialize;

use crate::error::AtlsVerificationError;

/// Enforce the OutOfDate grace period if configured.
pub fn enforce_grace_period(
    report: &VerifiedReport,
    quote: &Quote,
    collateral: &QuoteCollateralV3,
    grace_period: Option<u64>,
    now_secs: u64,
) -> Result<(), AtlsVerificationError> {
    let Some(grace) = grace_period else {
        return Ok(());
    };
    if report.status != "OutOfDate" {
        return Ok(());
    }

    let tcb_date = extract_tcb_date(quote, collateral)?;
    let tcb_date_secs = DateTime::parse_from_rfc3339(&tcb_date)
        .map_err(|e| AtlsVerificationError::TcbInfoError(format!("invalid TCB date: {}", e)))?
        .timestamp();

    evaluate_grace_period(&report.status, tcb_date_secs, &tcb_date, now_secs, grace)
}

fn evaluate_grace_period(
    status: &str,
    tcb_date_secs: i64,
    tcb_date: &str,
    now_secs: u64,
    grace: u64,
) -> Result<(), AtlsVerificationError> {
    let now_secs = i64::try_from(now_secs).map_err(|_| {
        AtlsVerificationError::TcbInfoError("current time out of range".into())
    })?;

    let grace_secs = i64::try_from(grace).map_err(|_| {
        AtlsVerificationError::Configuration("grace_period is too large".into())
    })?;
    let expiration = tcb_date_secs.checked_add(grace_secs).ok_or_else(|| {
        AtlsVerificationError::Configuration("grace_period causes timestamp overflow".into())
    })?;
    if expiration < now_secs {
        return Err(AtlsVerificationError::GracePeriodExpired {
            status: status.to_string(),
            tcb_date: tcb_date.to_string(),
            grace_period_secs: grace,
        });
    }

    Ok(())
}

// NOTE: The following Tcb* structs and matching logic are copied from dcap-qvl
// (src/tcb_info.rs and src/verify.rs) to extract the matched TCB date.
// TODO: Remove this duplication if dcap-qvl exposes these types/functions publicly.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfo {
    id: String,
    version: u8,
    fmspc: String,
    tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbLevel {
    tcb: Tcb,
    tcb_date: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Tcb {
    #[serde(rename = "sgxtcbcomponents")]
    sgx_components: Vec<TcbComponent>,
    #[serde(rename = "tdxtcbcomponents", default)]
    tdx_components: Vec<TcbComponent>,
    #[serde(rename = "pcesvn")]
    pce_svn: u16,
}

#[derive(Debug, Deserialize)]
struct TcbComponent {
    svn: u8,
}

fn extract_tcb_date(
    quote: &Quote,
    collateral: &QuoteCollateralV3,
) -> Result<String, AtlsVerificationError> {
    let tcb_info: TcbInfo = serde_json::from_str(&collateral.tcb_info).map_err(|e| {
        AtlsVerificationError::TcbInfoError(format!("failed to parse TCB info: {}", e))
    })?;

    let pck_leaf = extract_pck_leaf_cert(quote, collateral)?;
    let pck_extension = parse_pck_extension(&pck_leaf).map_err(|e| {
        AtlsVerificationError::TcbInfoError(format!("failed to parse PCK extension: {}", e))
    })?;

    let tcb_level = match_tcb_level(
        &tcb_info,
        quote,
        &pck_extension.cpu_svn,
        pck_extension.pce_svn,
        &pck_extension.fmspc,
    )?;

    Ok(tcb_level.tcb_date.clone())
}

fn extract_pck_leaf_cert(
    quote: &Quote,
    collateral: &QuoteCollateralV3,
) -> Result<Vec<u8>, AtlsVerificationError> {
    if let Some(pem_chain) = &collateral.pck_certificate_chain {
        let certs = parse_pem_chain(pem_chain)?;
        return certs.first().cloned().ok_or_else(|| {
            AtlsVerificationError::TcbInfoError(
                "PCK certificate chain is empty".to_string(),
            )
        });
    }

    let certs = dcap_qvl::intel::extract_cert_chain(quote).map_err(|e| {
        AtlsVerificationError::TcbInfoError(format!(
            "failed to extract PCK certificate chain from quote: {}",
            e
        ))
    })?;

    certs.first().cloned().ok_or_else(|| {
        AtlsVerificationError::TcbInfoError("PCK certificate chain is empty".to_string())
    })
}

fn parse_pem_chain(pem_chain: &str) -> Result<Vec<Vec<u8>>, AtlsVerificationError> {
    let certs = parse_many(pem_chain).map_err(|e| {
        AtlsVerificationError::TcbInfoError(format!(
            "failed to parse PCK certificate chain: {}",
            e
        ))
    })?;
    if certs.is_empty() {
        return Err(AtlsVerificationError::TcbInfoError(
            "failed to parse PCK certificate chain".to_string(),
        ));
    }
    Ok(certs.into_iter().map(|pem| pem.contents().to_vec()).collect())
}

fn match_tcb_level<'a>(
    tcb_info: &'a TcbInfo,
    quote: &Quote,
    cpu_svn: &[u8],
    pce_svn: u16,
    fmspc: &[u8],
) -> Result<&'a TcbLevel, AtlsVerificationError> {
    let tcb_fmspc = hex::decode(&tcb_info.fmspc).map_err(|e| {
        AtlsVerificationError::TcbInfoError(format!("failed to decode TCB FMSPC: {}", e))
    })?;
    if fmspc != tcb_fmspc.as_slice() {
        return Err(AtlsVerificationError::TcbInfoError(
            "FMSPC mismatch in TCB info".into(),
        ));
    }

    let is_tdx = quote.report.as_td10().is_some();
    if is_tdx {
        if tcb_info.version < 3 || tcb_info.id != "TDX" {
            return Err(AtlsVerificationError::TcbInfoError(
                "TDX quote with non-TDX TCB info".into(),
            ));
        }
    } else if tcb_info.version < 2 || tcb_info.id != "SGX" {
        return Err(AtlsVerificationError::TcbInfoError(
            "SGX quote with non-SGX TCB info".into(),
        ));
    }

    let td_report = if is_tdx {
        Some(quote.report.as_td10().ok_or_else(|| {
            AtlsVerificationError::TcbInfoError("failed to read TD report".into())
        })?)
    } else {
        None
    };

    for tcb_level in &tcb_info.tcb_levels {
        if pce_svn < tcb_level.tcb.pce_svn {
            continue;
        }

        let sgx_components: Vec<u8> =
            tcb_level.tcb.sgx_components.iter().map(|c| c.svn).collect();
        if sgx_components.is_empty() {
            return Err(AtlsVerificationError::TcbInfoError(
                "no SGX components in TCB info".into(),
            ));
        }

        if cpu_svn.iter().zip(&sgx_components).any(|(a, b)| a < b) {
            continue;
        }

        if let Some(td_report) = td_report {
            let tdx_components: Vec<u8> =
                tcb_level.tcb.tdx_components.iter().map(|c| c.svn).collect();
            if tdx_components.is_empty() {
                return Err(AtlsVerificationError::TcbInfoError(
                    "no TDX components in TCB info".into(),
                ));
            }
            if td_report
                .tee_tcb_svn
                .iter()
                .zip(&tdx_components)
                .any(|(a, b)| a < b)
            {
                continue;
            }
        }

        return Ok(tcb_level);
    }

    Err(AtlsVerificationError::TcbInfoError(
        "no matching TCB level found".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::evaluate_grace_period;
    use crate::error::AtlsVerificationError;

    #[test]
    fn test_grace_period_expired() {
        let result = evaluate_grace_period(
            "OutOfDate",
            100,
            "2024-01-01T00:00:00Z",
            200,
            50,
        );

        assert!(matches!(
            result,
            Err(AtlsVerificationError::GracePeriodExpired { .. })
        ));
    }

    #[test]
    fn test_grace_period_allows_within_window() {
        let result = evaluate_grace_period(
            "OutOfDate",
            100,
            "2024-01-01T00:00:00Z",
            120,
            50,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_grace_period_zero_expires_immediately() {
        let result = evaluate_grace_period(
            "OutOfDate",
            100,
            "2024-01-01T00:00:00Z",
            101,
            0,
        );

        assert!(matches!(
            result,
            Err(AtlsVerificationError::GracePeriodExpired { .. })
        ));
    }
}
