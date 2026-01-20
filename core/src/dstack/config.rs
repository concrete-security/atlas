//! Configuration types for DStack TDX verification.

use crate::tdx::ExpectedBootchain;

/// Configuration for DstackTDXVerifier.
///
/// This struct holds all the expected values and settings for TDX verification.
#[derive(Debug, Clone)]
pub struct DstackTDXVerifierConfig {
    /// Expected app compose configuration (as JSON Value for hash calculation).
    ///
    /// The verifier will compute the hash of this configuration and compare
    /// it against the hash in the TCB info and event log.
    pub app_compose: Option<serde_json::Value>,

    /// Allowed TCB statuses.
    ///
    /// Only attestations with TCB status in this list will be accepted.
    /// Default: `["UpToDate"]`
    pub allowed_tcb_status: Vec<String>,

    /// Disable runtime verification (NOT RECOMMENDED).
    ///
    /// When true, bootchain, app_compose, and os_image_hash verification
    /// will be skipped. This should only be used for testing.
    pub disable_runtime_verification: bool,

    /// Expected bootchain measurements.
    ///
    /// If provided, the verifier will check that the attestation's MRTD
    /// and RTMR0-2 match these expected values.
    pub expected_bootchain: Option<ExpectedBootchain>,

    /// Expected OS image hash.
    ///
    /// The SHA256 hash of the OS image that should be running in the TD.
    pub os_image_hash: Option<String>,

    /// PCCS URL for collateral fetching.
    ///
    /// If None, uses Intel's default PCS endpoint.
    pub pccs_url: Option<String>,

    /// Cache collateral to avoid repeated PCS fetches.
    ///
    /// When true (default), collateral fetched from PCS will be cached
    /// and reused for subsequent verifications.
    pub cache_collateral: bool,
}

impl Default for DstackTDXVerifierConfig {
    fn default() -> Self {
        Self {
            app_compose: None,
            allowed_tcb_status: vec!["UpToDate".to_string()],
            disable_runtime_verification: false,
            expected_bootchain: None,
            os_image_hash: None,
            pccs_url: None,
            cache_collateral: true,
        }
    }
}

/// Builder for DstackTDXVerifierConfig.
///
/// Provides a fluent API for constructing verifier configurations.
///
/// # Example
///
/// ```
/// use atls_core::dstack::{DstackTDXVerifierBuilder};
/// use atls_core::tdx::ExpectedBootchain;
/// use serde_json::json;
///
/// let verifier = DstackTDXVerifierBuilder::new()
///     .app_compose(json!({
///         "runner": "docker-compose",
///         "docker_compose_file": "..."
///     }))
///     .expected_bootchain(ExpectedBootchain {
///         mrtd: "abc123...".to_string(),
///         rtmr0: "def456...".to_string(),
///         rtmr1: "ghi789...".to_string(),
///         rtmr2: "jkl012...".to_string(),
///     })
///     .os_image_hash("sha256:...".to_string())
///     .build()
///     .unwrap();
/// ```
pub struct DstackTDXVerifierBuilder {
    config: DstackTDXVerifierConfig,
}

impl Default for DstackTDXVerifierBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DstackTDXVerifierBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: DstackTDXVerifierConfig::default(),
        }
    }

    /// Set the expected app compose configuration.
    pub fn app_compose(mut self, value: serde_json::Value) -> Self {
        self.config.app_compose = Some(value);
        self
    }

    /// Set the expected bootchain measurements.
    pub fn expected_bootchain(mut self, bootchain: ExpectedBootchain) -> Self {
        self.config.expected_bootchain = Some(bootchain);
        self
    }

    /// Set the expected OS image hash.
    pub fn os_image_hash(mut self, hash: impl Into<String>) -> Self {
        self.config.os_image_hash = Some(hash.into());
        self
    }

    /// Set the allowed TCB statuses.
    pub fn allowed_tcb_status(mut self, statuses: Vec<String>) -> Self {
        self.config.allowed_tcb_status = statuses;
        self
    }

    /// Set the PCCS URL for collateral fetching.
    pub fn pccs_url(mut self, url: impl Into<String>) -> Self {
        self.config.pccs_url = Some(url.into());
        self
    }

    /// Disable runtime verification (NOT RECOMMENDED).
    pub fn disable_runtime_verification(mut self) -> Self {
        self.config.disable_runtime_verification = true;
        self
    }

    /// Enable or disable collateral caching.
    pub fn cache_collateral(mut self, enabled: bool) -> Self {
        self.config.cache_collateral = enabled;
        self
    }

    /// Get the built configuration.
    pub fn into_config(self) -> DstackTDXVerifierConfig {
        self.config
    }

    /// Build the DstackTDXVerifier with the configured settings.
    pub fn build(self) -> Result<super::DstackTDXVerifier, crate::AtlsVerificationError> {
        super::DstackTDXVerifier::new(self.config)
    }
}
