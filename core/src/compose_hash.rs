//! Compose hash calculation module.
//!
//! Provides deterministic JSON serialization and SHA256 hashing of AppCompose
//! configurations, compatible with the Python and TypeScript implementations.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Recursively sort JSON object keys for deterministic output.
///
/// This is crucial for deterministic JSON.stringify across languages.
fn sort_object(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: serde_json::Map<String, Value> = map
                .into_iter()
                .map(|(k, v)| (k, sort_object(v)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_object).collect()),
        other => other,
    }
}

/// Calculate deterministic SHA256 hash of app compose configuration.
///
/// Compatible with Python/TypeScript implementations:
/// - Sorted keys lexicographically
/// - Compact output (no spaces)
/// - UTF-8 encoding
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
/// use ratls_core::compose_hash::get_compose_hash;
///
/// let compose = json!({
///     "runner": "docker-compose",
///     "docker_compose_file": "version: '3'\nservices:\n  app:\n    image: myapp"
/// });
///
/// let hash = get_compose_hash(&compose);
/// println!("Compose hash: {}", hash);
/// ```
pub fn get_compose_hash(app_compose: &Value) -> String {
    let sorted = sort_object(app_compose.clone());
    let json_str = serde_json::to_string(&sorted).unwrap();
    let hash = Sha256::digest(json_str.as_bytes());
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_sort_object() {
        let unsorted = json!({
            "z": 1,
            "a": 2,
            "m": {"b": 1, "a": 2}
        });

        let sorted = sort_object(unsorted);
        let json_str = serde_json::to_string(&sorted).unwrap();

        // Keys should be sorted alphabetically
        assert!(json_str.find("\"a\"").unwrap() < json_str.find("\"m\"").unwrap());
        assert!(json_str.find("\"m\"").unwrap() < json_str.find("\"z\"").unwrap());
    }

    #[test]
    fn test_get_compose_hash_deterministic() {
        let compose1 = json!({
            "runner": "docker-compose",
            "name": "test"
        });

        let compose2 = json!({
            "name": "test",
            "runner": "docker-compose"
        });

        // Same content, different key order should produce same hash
        assert_eq!(get_compose_hash(&compose1), get_compose_hash(&compose2));
    }

    #[test]
    fn test_get_compose_hash_different_content() {
        let compose1 = json!({
            "runner": "docker-compose",
            "name": "test1"
        });

        let compose2 = json!({
            "runner": "docker-compose",
            "name": "test2"
        });

        // Different content should produce different hash
        assert_ne!(get_compose_hash(&compose1), get_compose_hash(&compose2));
    }
}
