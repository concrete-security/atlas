//! Attestation policy types.
//!
//! This module provides the `Policy` enum that determines which verifier to use
//! and its configuration. Policies can be serialized/deserialized with serde,
//! making them easy to load from JSON configuration files.

use crate::{DstackTDXVerifier, DstackTDXVerifierBuilder, ExpectedBootchain, RatlsVerificationError};
use serde::{Deserialize, Serialize};

/// Default PCCS URL for TDX collateral fetching.
pub const DEFAULT_PCCS_URL: &str = "https://pccs.phala.network/tdx/certification/v4";

fn default_pccs_url() -> Option<String> {
    Some(DEFAULT_PCCS_URL.to_string())
}

/// Attestation policy determining which verifier to use and its configuration.
///
/// # Example
///
/// ```
/// use ratls_core::{Policy, DstackTdxPolicy};
///
/// // Default policy
/// let policy = Policy::default();
///
/// // Development policy with relaxed TCB status
/// let policy = Policy::DstackTdx(DstackTdxPolicy::dev());
///
/// // From JSON
/// let json = r#"{"type": "dstack_tdx", "allowed_tcb_status": ["UpToDate", "SWHardeningNeeded"]}"#;
/// let policy: Policy = serde_json::from_str(json).unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Policy {
    /// TDX attestation using dstack verifier.
    #[serde(rename = "dstack_tdx")]
    DstackTdx(DstackTdxPolicy),
}

impl Default for Policy {
    fn default() -> Self {
        Policy::DstackTdx(DstackTdxPolicy::default())
    }
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
}

fn default_allowed_tcb_status() -> Vec<String> {
    vec!["UpToDate".to_string()]
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
        }
    }
}

impl DstackTdxPolicy {
    /// Relaxed policy for development.
    ///
    /// Accepts common TCB statuses without requiring bootchain/app verification.
    pub fn dev() -> Self {
        Self {
            allowed_tcb_status: vec![
                "UpToDate".into(),
                "SWHardeningNeeded".into(),
                "OutOfDate".into(),
            ],
            ..Default::default()
        }
    }

    /// Convert this policy into a DstackTDXVerifier.
    pub(crate) fn into_verifier(self) -> Result<DstackTDXVerifier, RatlsVerificationError> {
        let mut builder = DstackTDXVerifierBuilder::new();

        // If no bootchain/app_compose/os_image specified, disable runtime verification
        let has_runtime_config = self.expected_bootchain.is_some()
            || self.app_compose.is_some()
            || self.os_image_hash.is_some();

        if !has_runtime_config {
            builder = builder.disable_runtime_verification();
        } else {
            if let Some(bootchain) = self.expected_bootchain {
                builder = builder.expected_bootchain(bootchain);
            }
            if let Some(app_compose) = self.app_compose {
                builder = builder.app_compose(app_compose);
            }
            if let Some(os_hash) = self.os_image_hash {
                builder = builder.os_image_hash(os_hash);
            }
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
    fn test_policy_default() {
        let policy = Policy::default();
        match policy {
            Policy::DstackTdx(tdx) => {
                assert_eq!(tdx.allowed_tcb_status, vec!["UpToDate"]);
                assert!(tdx.expected_bootchain.is_none());
            }
        }
    }

    #[test]
    fn test_policy_dev() {
        let policy = Policy::DstackTdx(DstackTdxPolicy::dev());
        match policy {
            Policy::DstackTdx(tdx) => {
                assert!(tdx.allowed_tcb_status.contains(&"SWHardeningNeeded".to_string()));
            }
        }
    }

    #[test]
    fn test_policy_json_roundtrip() {
        let policy = Policy::DstackTdx(DstackTdxPolicy {
            allowed_tcb_status: vec!["UpToDate".into(), "SWHardeningNeeded".into()],
            ..Default::default()
        });

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: Policy = serde_json::from_str(&json).unwrap();

        match parsed {
            Policy::DstackTdx(tdx) => {
                assert_eq!(tdx.allowed_tcb_status.len(), 2);
            }
        }
    }

    #[test]
    fn test_policy_from_json() {
        let json = r#"{"type": "dstack_tdx", "allowed_tcb_status": ["UpToDate"]}"#;
        let policy: Policy = serde_json::from_str(json).unwrap();

        match policy {
            Policy::DstackTdx(tdx) => {
                assert_eq!(tdx.allowed_tcb_status, vec!["UpToDate"]);
            }
        }
    }
}
