//! DStack-specific policy types.

use crate::dstack::{DstackTDXVerifier, DstackTDXVerifierBuilder};
use crate::tdx::{ExpectedBootchain, TCB_STATUS_LIST};
use crate::verifier::IntoVerifier;
use crate::RatlsVerificationError;
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

    /// Allowed TCB status values.
    #[serde(default = "default_allowed_tcb_status")]
    pub allowed_tcb_status: Vec<String>,

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
}

impl Default for DstackTdxPolicy {
    fn default() -> Self {
        Self {
            expected_bootchain: None,
            app_compose: None,
            os_image_hash: None,
            allowed_tcb_status: default_allowed_tcb_status(),
            pccs_url: default_pccs_url(),
            cache_collateral: false,
            disable_runtime_verification: false,
        }
    }
}

/// Check if a string is a valid lowercase hex string.
fn is_valid_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
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
    pub fn validate(&self) -> Result<(), RatlsVerificationError> {
        // Validate TCB status values
        for status in &self.allowed_tcb_status {
            if !TCB_STATUS_LIST.contains(&status.as_str()) {
                return Err(RatlsVerificationError::Configuration(format!(
                    "invalid TCB status '{}', valid values are: {:?}",
                    status, TCB_STATUS_LIST
                )));
            }
        }

        // Validate os_image_hash is hex
        if let Some(ref hash) = self.os_image_hash {
            if !is_valid_hex(hash) {
                return Err(RatlsVerificationError::Configuration(
                    "os_image_hash must be a lowercase hex string".into(),
                ));
            }
        }

        // Validate bootchain fields are hex
        if let Some(ref bootchain) = self.expected_bootchain {
            if !is_valid_hex(&bootchain.mrtd) {
                return Err(RatlsVerificationError::Configuration(
                    "expected_bootchain.mrtd must be a lowercase hex string".into(),
                ));
            }
            if !is_valid_hex(&bootchain.rtmr0) {
                return Err(RatlsVerificationError::Configuration(
                    "expected_bootchain.rtmr0 must be a lowercase hex string".into(),
                ));
            }
            if !is_valid_hex(&bootchain.rtmr1) {
                return Err(RatlsVerificationError::Configuration(
                    "expected_bootchain.rtmr1 must be a lowercase hex string".into(),
                ));
            }
            if !is_valid_hex(&bootchain.rtmr2) {
                return Err(RatlsVerificationError::Configuration(
                    "expected_bootchain.rtmr2 must be a lowercase hex string".into(),
                ));
            }
        }

        Ok(())
    }
}

impl IntoVerifier for DstackTdxPolicy {
    type Verifier = DstackTDXVerifier;

    fn into_verifier(self) -> Result<DstackTDXVerifier, RatlsVerificationError> {
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

        builder = builder.allowed_tcb_status(self.allowed_tcb_status);

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

    #[test]
    fn test_dstack_tdx_policy_default() {
        let policy = DstackTdxPolicy::default();
        assert_eq!(policy.allowed_tcb_status, vec!["UpToDate"]);
        assert!(policy.expected_bootchain.is_none());
        assert!(!policy.disable_runtime_verification);
    }

    #[test]
    fn test_dstack_tdx_policy_dev() {
        let policy = DstackTdxPolicy::dev();
        assert!(policy.allowed_tcb_status.contains(&"SWHardeningNeeded".to_string()));
        assert!(policy.disable_runtime_verification);
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
