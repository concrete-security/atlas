//! Dstack-specific TDX verifier implementation.
//!
//! This module contains the `DstackTDXVerifier` and related types
//! specific to dstack deployments.

pub mod compose_hash;
pub mod config;
pub mod default_app_compose;
pub mod policy;
mod verifier;

pub use config::{DstackTDXVerifierBuilder, DstackTDXVerifierConfig};
pub use default_app_compose::{get_default_app_compose, merge_with_default_app_compose};
pub use policy::DstackTdxPolicy;
pub use verifier::DstackTDXVerifier;
