//! Compose hash calculation module.
//!
//! Provides SHA256 hashing of AppCompose configurations.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Calculate SHA256 hash of app compose configuration.
///
///
/// # Arguments
///
/// * `app_compose` - The app compose configuration as a JSON Value
///
/// # Returns
///
/// SHA256 hash as a lowercase hex string
///
/// # Example
///
/// ```
/// use serde_json::json;
/// use ratls_core::dstack::compose_hash::get_compose_hash;
///
/// let compose = json!({
///     "docker_compose_file": "version: '3'\nservices:\n  app:\n    image: myapp",
///     "runner": "docker-compose"
/// });
///
/// let hash = get_compose_hash(&compose);
/// println!("Compose hash: {}", hash);
/// ```
pub fn get_compose_hash(app_compose: &Value) -> String {
    let json_str = serde_json::to_string(app_compose).unwrap();
    let hash = Sha256::digest(json_str.as_bytes());
    hex::encode(hash)
}
