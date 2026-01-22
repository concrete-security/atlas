//! Attestation policy types.
//!
//! This module provides the `Policy` enum that determines which verifier to use
//! and its configuration. Policies can be serialized/deserialized with serde,
//! making them easy to load from JSON configuration files.

use crate::dstack::DstackTdxPolicy;
use crate::error::AtlsVerificationError;
use crate::verifier::{IntoVerifier, Verifier};
use serde::{Deserialize, Serialize};

/// Attestation policy determining which verifier to use and its configuration.
///
/// # Example
///
/// ```
/// use atls_core::{Policy, DstackTdxPolicy};
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

impl Policy {
    /// Convert this policy into its corresponding verifier.
    ///
    /// This delegates to the underlying policy variant's [`IntoVerifier`] implementation,
    /// wrapping the result in the [`Verifier`] enum for type-safe polymorphism.
    ///
    /// # Example
    ///
    /// ```
    /// use atls_core::{Policy, DstackTdxPolicy};
    ///
    /// let policy = Policy::DstackTdx(DstackTdxPolicy::dev());
    /// let verifier = policy.into_verifier().unwrap();
    /// ```
    pub fn into_verifier(self) -> Result<Verifier, AtlsVerificationError> {
        match self {
            Policy::DstackTdx(policy) => {
                Ok(Verifier::DstackTdx(policy.into_verifier()?))
            }
        }
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
