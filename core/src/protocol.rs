use crate::platform::{AsyncReadExt, AsyncWriteExt, TlsStream};
use crate::tdx;
use crate::{AsyncByteStream, AttestationEndpoint, AttestationResult, Policy, RatlsError};
use dcap_qvl::QuoteCollateralV3;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize)]
struct AttestationRequest {
    report_data: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AttestationResponse {
    Success {
        quote: DstackQuote,
        #[serde(default)]
        collateral: Option<QuoteCollateralV3>,
    },
    Error {
        error: String,
    },
}

#[derive(Deserialize)]
struct DstackQuote {
    quote: String,
    #[serde(default)]
    event_log: Value,
}

pub async fn verify_attestation_stream<S>(
    stream: &mut TlsStream<S>,
    server_cert: &[u8],
    policy: &Policy,
    endpoint: &AttestationEndpoint,
) -> Result<AttestationResult, RatlsError>
where
    S: AsyncByteStream,
{
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);

    let body_json = serde_json::to_string(&AttestationRequest {
        report_data: nonce_hex.clone(),
    })
    .map_err(|e| RatlsError::Io(e.to_string()))?;
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         {}",
        endpoint.path,
        body_json.len(),
        body_json
    );

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;

    let mut header_buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| RatlsError::Io(e.to_string()))?;
        header_buffer.push(byte[0]);
        if header_buffer.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buffer.len() > 8192 {
            return Err(RatlsError::Io("HTTP header too large".into()));
        }
    }

    let headers_str = String::from_utf8_lossy(&header_buffer);
    if !headers_str.starts_with("HTTP/1.1 200 OK") {
        let status_line = headers_str.lines().next().unwrap_or_default();
        return Err(RatlsError::Vendor(format!(
            "Server returned error: {status_line}"
        )));
    }

    let len_prefix = "content-length: ";
    let content_len = headers_str
        .to_lowercase()
        .lines()
        .find(|line| line.starts_with(len_prefix))
        .ok_or_else(|| RatlsError::Io("Missing Content-Length".into()))
        .and_then(|line| {
            line[len_prefix.len()..]
                .trim()
                .parse::<usize>()
                .map_err(|_| RatlsError::Io("Invalid Content-Length".into()))
        })?;

    let mut body = vec![0u8; content_len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;

    let response: AttestationResponse = serde_json::from_slice(&body)
        .map_err(|e| RatlsError::Vendor(format!("Invalid server response: {e}")))?;

    let (dstack_quote, response_collateral) = match response {
        AttestationResponse::Success { quote, collateral } => (quote, collateral),
        AttestationResponse::Error { error } => return Err(RatlsError::Vendor(error)),
    };

    let quote_bytes = hex::decode(&dstack_quote.quote)
        .map_err(|e| RatlsError::Vendor(format!("Invalid quote hex: {e}")))?;
    let event_log = tdx::parse_event_log(dstack_quote.event_log)?;

    let collateral = if let Some(collateral) = response_collateral {
        collateral
    } else if let Some(pccs) = policy.pccs_url.as_deref() {
        dcap_qvl::collateral::get_collateral(pccs, &quote_bytes)
            .await
            .map_err(|e| RatlsError::Vendor(format!("Failed to fetch collateral: {e}")))?
    } else {
        return Err(RatlsError::Policy(
            "Server did not provide collateral and no PCCS configured".into(),
        ));
    };

    let attestation = tdx::verify_attestation(&quote_bytes, &collateral, policy).await?;

    tdx::verify_quote_freshness(&quote_bytes, nonce_hex.as_bytes())?;
    tdx::verify_event_log_integrity(&quote_bytes, &event_log)?;

    tdx::verify_tls_certificate_in_log(&event_log, server_cert)?;

    Ok(attestation)
}
