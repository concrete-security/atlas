//! DStack-specific policy types.

use crate::dstack::{DstackTDXVerifier, DstackTDXVerifierBuilder};
use crate::tdx::{ExpectedBootchain, TCB_STATUS_LIST};
use crate::verifier::IntoVerifier;
use crate::AtlsVerificationError;
use serde::{Deserialize, Serialize};

/// Default PCCS URL for TDX collateral fetching.
pub const DEFAULT_PCCS_URL: &str = "https://pccs.phala.network/tdx/certification/v4";

fn default_pccs_url() -> Option<String> {
    Some(DEFAULT_PCCS_URL.to_string())
}

fn default_allowed_tcb_status() -> Vec<String> {
    vec!["UpToDate".to_string()]
}

/// Policy configuration for dstack TDX verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DstackTdxPolicy {
    /// Expected bootchain measurements (MRTD, RTMR0-2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_bootchain: Option<ExpectedBootchain>,

    /// Expected app compose configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_compose: Option<serde_json::Value>,

    /// Expected OS image hash (SHA256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_image_hash: Option<String>,

    /// Expected RTMR3 - full runtime measurement register (96 lowercase hex
    /// chars, i.e. a SHA384 digest).
    ///
    /// RTMR3 accumulates the application runtime events (compose hash, OS image
    /// hash, TLS certificate, ...). Pinning it constrains the whole runtime
    /// event sequence, not just the individual events checked by
    /// `app_compose` / `os_image_hash`.
    ///
    /// When absent (the default), no RTMR3 check is performed, so existing
    /// policies keep their current behavior. Like the other runtime checks, it
    /// is skipped when `disable_runtime_verification` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_rtmr3: Option<String>,

    /// Allowed TCB status values.
    #[serde(default = "default_allowed_tcb_status")]
    pub allowed_tcb_status: Vec<String>,

    /// Grace period (seconds) for OutOfDate platforms.
    ///
    /// If set and the platform TCB status is OutOfDate, the platform is allowed
    /// only if its TCB date plus this duration is >= current time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_period: Option<u64>,

    /// PCCS URL for collateral fetching.
    /// Defaults to `https://pccs.phala.network/tdx/certification/v4`.
    #[serde(default = "default_pccs_url", skip_serializing_if = "Option::is_none")]
    pub pccs_url: Option<String>,

    /// Cache collateral to avoid repeated fetches.
    #[serde(default)]
    pub cache_collateral: bool,

    /// Disable runtime verification (NOT RECOMMENDED for production).
    ///
    /// When false (default), all runtime fields (expected_bootchain, app_compose,
    /// os_image_hash) must be provided or verification will fail.
    /// Set to true only for development/testing.
    #[serde(default)]
    pub disable_runtime_verification: bool,

    /// Accept the server's TLS certificate without CA-chain, hostname/SAN, or
    /// expiry validation (for TEE self-signed certs).
    ///
    /// **Defaults to `false`** — standard webpki-roots CA + hostname validation
    /// applies. Set to `true` only for TEEs that serve self-signed certificates,
    /// where trust comes from attestation (the DCAP quote binds the leaf cert via
    /// the event log, plus EKM session binding). The handshake signature is always
    /// verified, so the peer must hold the certificate's private key regardless.
    ///
    /// Because this drops the hostname check, it removes the only per-connection
    /// endpoint binding at the TLS layer; `expected_rtmr3` is required to bind the
    /// specific instance. It is also rejected together with
    /// `disable_runtime_verification` (that combination pins neither identity nor
    /// measurements).
    #[serde(default)]
    pub accept_self_signed_certs: bool,
}

impl Default for DstackTdxPolicy {
    fn default() -> Self {
        Self {
            expected_bootchain: None,
            app_compose: None,
            os_image_hash: None,
            expected_rtmr3: None,
            allowed_tcb_status: default_allowed_tcb_status(),
            grace_period: None,
            pccs_url: default_pccs_url(),
            cache_collateral: false,
            disable_runtime_verification: false,
            accept_self_signed_certs: false,
        }
    }
}

/// Check if a string is a valid lowercase hex string.
fn is_valid_hex(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

impl DstackTdxPolicy {
    /// Relaxed policy for development.
    ///
    /// Accepts common TCB statuses and disables runtime verification
    /// (bootchain, app_compose, os_image_hash checks are skipped).
    pub fn dev() -> Self {
        Self {
            disable_runtime_verification: true,
            allowed_tcb_status: vec![
                "UpToDate".into(),
                "SWHardeningNeeded".into(),
                "OutOfDate".into(),
            ],
            ..Default::default()
        }
    }

    /// Validate the policy configuration.
    ///
    /// Checks that:
    /// - `allowed_tcb_status` values are valid TCB status strings
    /// - `os_image_hash` is a valid hex string (if provided)
    /// - `expected_bootchain` fields are valid hex strings (if provided)
    /// - `grace_period` requires `allowed_tcb_status` to include `OutOfDate`
    /// - `accept_self_signed_certs` is not combined with `disable_runtime_verification`
    /// - `accept_self_signed_certs` is bound to a specific instance by `expected_rtmr3`
    pub fn validate(&self) -> Result<(), AtlsVerificationError> {
        // Validate TCB status values
        for status in &self.allowed_tcb_status {
            if !TCB_STATUS_LIST.contains(&status.as_str()) {
                return Err(AtlsVerificationError::Configuration(format!(
                    "invalid TCB status '{}', valid values are: {:?}",
                    status, TCB_STATUS_LIST
                )));
            }
        }

        // Skipping certificate validation AND runtime verification together leaves
        // no CA trust, no hostname binding, and no measurement pinning — the peer is
        // authenticated as nothing more than "some TDX machine". Reject the combination.
        if self.accept_self_signed_certs && self.disable_runtime_verification {
            return Err(AtlsVerificationError::Configuration(
                "accept_self_signed_certs cannot be combined with disable_runtime_verification"
                    .into(),
            ));
        }
        if self.accept_self_signed_certs && self.expected_rtmr3.is_none() {
            return Err(AtlsVerificationError::Configuration(
                "accept_self_signed_certs requires expected_rtmr3".into(),
            ));
        }

        // Validate grace period policy requirements
        if self.grace_period.is_some() && !self.allowed_tcb_status.iter().any(|s| s == "OutOfDate")
        {
            return Err(AtlsVerificationError::Configuration(
                "grace_period requires allowed_tcb_status to include OutOfDate".into(),
            ));
        }

        // Validate os_image_hash is hex
        if let Some(ref hash) = self.os_image_hash {
            if !is_valid_hex(hash) {
                return Err(AtlsVerificationError::Configuration(
                    "os_image_hash must be a lowercase hex string".into(),
                ));
            }
        }

        // Validate bootchain fields are hex
        if let Some(ref bootchain) = self.expected_bootchain {
            if !is_valid_hex(&bootchain.mrtd) {
                return Err(AtlsVerificationError::Configuration(
                    "expected_bootchain.mrtd must be a lowercase hex string".into(),
                ));
            }
            if !is_valid_hex(&bootchain.rtmr0) {
                return Err(AtlsVerificationError::Configuration(
                    "expected_bootchain.rtmr0 must be a lowercase hex string".into(),
                ));
            }
            if !is_valid_hex(&bootchain.rtmr1) {
                return Err(AtlsVerificationError::Configuration(
                    "expected_bootchain.rtmr1 must be a lowercase hex string".into(),
                ));
            }
            if !is_valid_hex(&bootchain.rtmr2) {
                return Err(AtlsVerificationError::Configuration(
                    "expected_bootchain.rtmr2 must be a lowercase hex string".into(),
                ));
            }
        }

        // Validate expected_rtmr3 is a full SHA384 measurement (48 bytes = 96 hex chars)
        if let Some(ref rtmr3) = self.expected_rtmr3 {
            if !is_valid_hex(rtmr3) || rtmr3.len() != 96 {
                return Err(AtlsVerificationError::Configuration(
                    "expected_rtmr3 must be a 96-character lowercase hex string".into(),
                ));
            }
        }

        Ok(())
    }
}

impl IntoVerifier for DstackTdxPolicy {
    type Verifier = DstackTDXVerifier;

    fn into_verifier(self) -> Result<DstackTDXVerifier, AtlsVerificationError> {
        // Validate configuration before building
        self.validate()?;

        let mut builder = DstackTDXVerifierBuilder::new();

        // Only disable runtime verification if explicitly requested
        if self.disable_runtime_verification {
            builder = builder.disable_runtime_verification();
        }

        // Pass all fields through - validation happens in DstackTDXVerifier::new()
        if let Some(bootchain) = self.expected_bootchain {
            builder = builder.expected_bootchain(bootchain);
        }
        if let Some(app_compose) = self.app_compose {
            builder = builder.app_compose(app_compose);
        }
        if let Some(os_hash) = self.os_image_hash {
            builder = builder.os_image_hash(os_hash);
        }
        if let Some(rtmr3) = self.expected_rtmr3 {
            builder = builder.expected_rtmr3(rtmr3);
        }

        builder = builder.allowed_tcb_status(self.allowed_tcb_status);
        if let Some(grace) = self.grace_period {
            builder = builder.grace_period(grace);
        }

        if let Some(pccs) = self.pccs_url {
            builder = builder.pccs_url(pccs);
        }

        builder = builder.cache_collateral(self.cache_collateral);

        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed RTMR3 pin (48 bytes = 96 hex chars).
    const TEST_RTMR3: &str = "1f2e3d4c5b6a79880716253443526170a1b2c3d4e5f60718293a4b5c6d7e8f900a1b2c3d4e5f60718293a4b5c6d7e8f9";

    #[test]
    fn test_dstack_tdx_policy_default() {
        let policy = DstackTdxPolicy::default();
        assert_eq!(policy.allowed_tcb_status, vec!["UpToDate"]);
        assert!(policy.expected_bootchain.is_none());
        assert!(policy.expected_rtmr3.is_none());
        assert!(!policy.disable_runtime_verification);
        // Safe default: CA + hostname validation applies unless explicitly opted out.
        assert!(!policy.accept_self_signed_certs);
    }

    #[test]
    fn test_dstack_tdx_policy_dev() {
        let policy = DstackTdxPolicy::dev();
        assert!(policy
            .allowed_tcb_status
            .contains(&"SWHardeningNeeded".to_string()));
        assert!(policy.disable_runtime_verification);
        // dev() must not also skip cert validation — that combination is rejected.
        assert!(!policy.accept_self_signed_certs);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_self_signed_with_disable_runtime_rejected() {
        // Skipping cert validation AND runtime verification pins nothing — rejected.
        let policy = DstackTdxPolicy {
            accept_self_signed_certs: true,
            disable_runtime_verification: true,
            expected_rtmr3: Some(TEST_RTMR3.into()),
            ..Default::default()
        };
        let err = policy
            .validate()
            .expect_err("self-signed + disable_runtime must be rejected")
            .to_string();
        assert!(
            err.contains(
                "accept_self_signed_certs cannot be combined with disable_runtime_verification"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_self_signed_without_rtmr3_rejected() {
        let policy = DstackTdxPolicy {
            accept_self_signed_certs: true,
            ..Default::default()
        };

        let err = policy
            .validate()
            .expect_err("self-signed certificate acceptance must require an RTMR3 pin")
            .to_string();

        assert!(
            err.contains("accept_self_signed_certs requires expected_rtmr3"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_self_signed_with_rtmr3_accepted() {
        let policy = DstackTdxPolicy {
            expected_rtmr3: Some(TEST_RTMR3.into()),
            accept_self_signed_certs: true,
            ..Default::default()
        };

        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_valid_rtmr3_accepted() {
        let policy = DstackTdxPolicy {
            expected_rtmr3: Some(TEST_RTMR3.into()),
            disable_runtime_verification: true,
            ..Default::default()
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_invalid_rtmr3_rejected() {
        // A malformed pin must be caught at load time, not silently at compare time.
        for bad in [
            "not-valid-hex!",
            &TEST_RTMR3.to_uppercase(),
            &TEST_RTMR3[..94], // 94 hex chars: valid hex, wrong length
            "",
        ] {
            let policy = DstackTdxPolicy {
                expected_rtmr3: Some(bad.into()),
                disable_runtime_verification: true,
                ..Default::default()
            };
            let err = policy
                .validate()
                .expect_err("malformed expected_rtmr3 must be rejected")
                .to_string();
            assert!(
                err.contains("expected_rtmr3 must be a 96-character lowercase hex string"),
                "unexpected error for {:?}: {}",
                bad,
                err
            );
        }
    }

    #[test]
    fn test_rtmr3_json_optional() {
        // Policies written before RTMR3 pinning existed must keep parsing, and
        // must not gain the key when serialized back out.
        let without: DstackTdxPolicy =
            serde_json::from_str(r#"{"allowed_tcb_status": ["UpToDate"]}"#).unwrap();
        assert!(without.expected_rtmr3.is_none());
        assert!(!serde_json::to_string(&without)
            .unwrap()
            .contains("expected_rtmr3"));

        let with: DstackTdxPolicy =
            serde_json::from_str(&format!(r#"{{"expected_rtmr3": "{}"}}"#, TEST_RTMR3)).unwrap();
        assert_eq!(with.expected_rtmr3.as_deref(), Some(TEST_RTMR3));
    }

    #[test]
    fn test_dstack_tdx_policy_json_roundtrip() {
        let policy = DstackTdxPolicy {
            allowed_tcb_status: vec!["UpToDate".into(), "SWHardeningNeeded".into()],
            ..Default::default()
        };

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: DstackTdxPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.allowed_tcb_status.len(), 2);
    }

    #[test]
    fn test_default_policy_requires_all_fields() {
        // Default policy with no runtime fields should fail to build verifier
        let policy = DstackTdxPolicy::default();
        let result = policy.into_verifier();
        assert!(result.is_err());
    }

    #[test]
    fn test_dev_policy_builds_without_runtime_fields() {
        // Dev policy explicitly disables runtime verification
        let policy = DstackTdxPolicy::dev();
        let result = policy.into_verifier();
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_tcb_status_rejected() {
        let policy = DstackTdxPolicy {
            allowed_tcb_status: vec!["InvalidStatus".into()],
            disable_runtime_verification: true,
            ..Default::default()
        };
        let result = policy.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid TCB status"));
    }

    #[test]
    fn test_grace_period_requires_out_of_date_status() {
        let policy = DstackTdxPolicy {
            grace_period: Some(0),
            allowed_tcb_status: vec!["UpToDate".into()],
            disable_runtime_verification: true,
            ..Default::default()
        };
        let result = policy.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("grace_period requires"));
    }

    #[test]
    fn test_grace_period_with_out_of_date_status_allowed() {
        let policy = DstackTdxPolicy {
            grace_period: Some(3600),
            allowed_tcb_status: vec!["UpToDate".into(), "OutOfDate".into()],
            disable_runtime_verification: true,
            ..Default::default()
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_invalid_hex_os_image_hash_rejected() {
        let policy = DstackTdxPolicy {
            os_image_hash: Some("not-valid-hex!".into()),
            disable_runtime_verification: true,
            ..Default::default()
        };
        let result = policy.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("os_image_hash must be a lowercase hex string"));
    }

    #[test]
    fn test_uppercase_hex_rejected() {
        let policy = DstackTdxPolicy {
            os_image_hash: Some("ABCD1234".into()),
            disable_runtime_verification: true,
            ..Default::default()
        };
        let result = policy.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_hex_accepted() {
        let policy = DstackTdxPolicy {
            os_image_hash: Some("abcd1234".into()),
            disable_runtime_verification: true,
            ..Default::default()
        };
        let result = policy.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_bootchain_hex_rejected() {
        let policy = DstackTdxPolicy {
            expected_bootchain: Some(ExpectedBootchain {
                mrtd: "invalid_hex".into(),
                rtmr0: "abc123".into(),
                rtmr1: "def456".into(),
                rtmr2: "789abc".into(),
            }),
            disable_runtime_verification: true,
            ..Default::default()
        };
        let result = policy.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mrtd"));
    }
}
