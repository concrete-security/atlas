//! Default app compose configuration for dstack deployments.

use serde_json::{json, Value};

/// The default pre-launch script for dstack deployments (Phala Cloud v0.0.10).
///
/// This script handles Docker registry login, cleanup, root password setup,
/// SSH key configuration, and dstack environment variables.
const DEFAULT_PRE_LAUNCH_SCRIPT: &str = r#"#!/bin/bash
echo "----------------------------------------------"
echo "Running Phala Cloud Pre-Launch Script v0.0.10"
echo "----------------------------------------------"
set -e

# Function: notify host

notify_host() {
    if command -v dstack-util >/dev/null 2>&1; then
        dstack-util notify-host -e "$1" -d "$2"
    else
        tdxctl notify-host -e "$1" -d "$2"
    fi
}

notify_host_hoot_info() {
    notify_host "boot.progress" "$1"
}

notify_host_hoot_error() {
    notify_host "boot.error" "$1"
}

# Function: Perform Docker cleanup
perform_cleanup() {
    echo "Pruning unused images"
    docker image prune -af
    echo "Pruning unused volumes"
    docker volume prune -f
    notify_host_hoot_info "docker cleanup completed"
}

# Function: Check Docker login status without exposing credentials
check_docker_login() {
    # Try to verify login status without exposing credentials
    if docker info 2>/dev/null | grep -q "Username"; then
        return 0
    else
        return 1
    fi
}

# Main logic starts here
echo "Starting login process..."

# Check if Docker credentials exist
if [[ -n "$DSTACK_DOCKER_USERNAME" && -n "$DSTACK_DOCKER_PASSWORD" ]]; then
    echo "Docker credentials found"
    
    # Check if already logged in
    if check_docker_login; then
        echo "Already logged in to Docker registry"
    else
        echo "Logging in to Docker registry..."
        # Login without exposing password in process list
        if [[ -n "$DSTACK_DOCKER_REGISTRY" ]]; then
            echo "$DSTACK_DOCKER_PASSWORD" | docker login -u "$DSTACK_DOCKER_USERNAME" --password-stdin "$DSTACK_DOCKER_REGISTRY"
        else
            echo "$DSTACK_DOCKER_PASSWORD" | docker login -u "$DSTACK_DOCKER_USERNAME" --password-stdin
        fi
        
        if [ $? -eq 0 ]; then
            echo "Docker login successful"
        else
            echo "Docker login failed"
            notify_host_hoot_error "docker login failed"
            exit 1
        fi
    fi
# Check if AWS ECR credentials exist
elif [[ -n "$DSTACK_AWS_ACCESS_KEY_ID" && -n "$DSTACK_AWS_SECRET_ACCESS_KEY" && -n "$DSTACK_AWS_REGION" && -n "$DSTACK_AWS_ECR_REGISTRY" ]]; then
    echo "AWS ECR credentials found"
    
    # Check if AWS CLI is installed
    if [ ! -f "./aws/dist/aws" ]; then
        notify_host_hoot_info "awscli not installed, installing..."
        echo "AWS CLI not installed, installing..."
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.24.14.zip" -o "awscliv2.zip"
        echo "6ff031a26df7daebbfa3ccddc9af1450 awscliv2.zip" | md5sum -c
        if [ $? -ne 0 ]; then
            echo "MD5 checksum failed"
            notify_host_hoot_error "awscli install failed"
            exit 1
        fi
        unzip awscliv2.zip &> /dev/null
    else
        echo "AWS CLI is already installed: ./aws/dist/aws"
    fi

    # Set AWS credentials as environment variables
    export AWS_ACCESS_KEY_ID="$DSTACK_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$DSTACK_AWS_SECRET_ACCESS_KEY"
    export AWS_DEFAULT_REGION="$DSTACK_AWS_REGION"
    
    # Set session token if provided (for temporary credentials)
    if [[ -n "$DSTACK_AWS_SESSION_TOKEN" ]]; then
        echo "AWS session token found, using temporary credentials"
        export AWS_SESSION_TOKEN="$DSTACK_AWS_SESSION_TOKEN"
    fi
    
    # Test AWS credentials before attempting ECR login
    echo "Testing AWS credentials..."
    if ! ./aws/dist/aws sts get-caller-identity &> /dev/null; then
        echo "AWS credentials test failed"
        # For session token credentials, this might be expected if they're expired
        # Log warning but don't fail startup
        if [[ -n "$DSTACK_AWS_SESSION_TOKEN" ]]; then
            echo "Warning: AWS temporary credentials may have expired, continuing startup"
            notify_host_hoot_info "AWS temporary credentials may have expired"
        else
            echo "AWS credentials test failed"
            notify_host_hoot_error "Invalid AWS credentials"
            exit 1
        fi
    else
        echo "Logging in to AWS ECR..."
        ./aws/dist/aws ecr get-login-password --region $DSTACK_AWS_REGION | docker login --username AWS --password-stdin "$DSTACK_AWS_ECR_REGISTRY"
        if [ $? -eq 0 ]; then
            echo "AWS ECR login successful"
            notify_host_hoot_info "AWS ECR login successful"
        else
            echo "AWS ECR login failed"
            # For session token credentials, don't fail startup if login fails
            if [[ -n "$DSTACK_AWS_SESSION_TOKEN" ]]; then
                echo "Warning: AWS ECR login failed with temporary credentials, continuing startup"
                notify_host_hoot_info "AWS ECR login failed with temporary credentials"
            else
                notify_host_hoot_error "AWS ECR login failed"
                exit 1
            fi
        fi
    fi
fi

perform_cleanup

#
# Set root password.
#
if [ -n "$DSTACK_ROOT_PASSWORD" ]; then
    echo "$DSTACK_ROOT_PASSWORD" | passwd --stdin root 2>/dev/null         || printf '%s
%s
' "$DSTACK_ROOT_PASSWORD" "$DSTACK_ROOT_PASSWORD" | passwd root
    unset DSTACK_ROOT_PASSWORD
    echo "Root password set/updated from DSTACK_ROOT_PASSWORD"

elif [ -z "$(grep '^root:' /etc/shadow 2>/dev/null | cut -d: -f2)" ]; then
    DSTACK_ROOT_PASSWORD=$(
        dd if=/dev/urandom bs=32 count=1 2>/dev/null         | sha256sum         | awk '{print $1}'         | cut -c1-32
    )
    echo "$DSTACK_ROOT_PASSWORD" | passwd --stdin root 2>/dev/null         || printf '%s
%s
' "$DSTACK_ROOT_PASSWORD" "$DSTACK_ROOT_PASSWORD" | passwd root
    unset DSTACK_ROOT_PASSWORD
    echo "Root password set (random auto-init)"

else
    echo "Root password already set; no changes."
fi

if [[ -n "$DSTACK_ROOT_PUBLIC_KEY" ]]; then
    mkdir -p /home/root/.ssh
    echo "$DSTACK_ROOT_PUBLIC_KEY" > /home/root/.ssh/authorized_keys
    unset $DSTACK_ROOT_PUBLIC_KEY
    echo "Root public key set"
fi
if [[ -n "$DSTACK_AUTHORIZED_KEYS" ]]; then
    mkdir -p /home/root/.ssh
    echo "$DSTACK_AUTHORIZED_KEYS" > /home/root/.ssh/authorized_keys
    unset $DSTACK_AUTHORIZED_KEYS
    echo "Root authorized_keys set"
fi


if [[ -S /var/run/dstack.sock ]]; then
    export DSTACK_APP_ID=$(curl -s --unix-socket /var/run/dstack.sock http://dstack/Info | jq -j .app_id)
elif [[ -S /var/run/tappd.sock ]]; then
    export DSTACK_APP_ID=$(curl -s --unix-socket /var/run/tappd.sock http://dstack/prpc/Tappd.Info | jq -j .app_id)
fi
# Check if DSTACK_GATEWAY_DOMAIN is not set, try to get it from user_config or app-compose.json
# Priority: user_config > app-compose.json
if [[ -z "$DSTACK_GATEWAY_DOMAIN" ]]; then
    # First try to get from /dstack/user_config if it exists and is valid JSON
    if [[ -f /dstack/user_config ]] && jq empty /dstack/user_config 2>/dev/null; then
        if [[ $(jq 'has("default_gateway_domain")' /dstack/user_config 2>/dev/null) == "true" ]]; then
            export DSTACK_GATEWAY_DOMAIN=$(jq -j '.default_gateway_domain' /dstack/user_config)
        fi
    fi

    # If still not set, try to get from app-compose.json
    if [[ -z "$DSTACK_GATEWAY_DOMAIN" ]] && [[ $(jq 'has("default_gateway_domain")' app-compose.json) == "true" ]]; then
        export DSTACK_GATEWAY_DOMAIN=$(jq -j '.default_gateway_domain' app-compose.json)
    fi
fi
if [[ -n "$DSTACK_GATEWAY_DOMAIN" ]]; then
    export DSTACK_APP_DOMAIN=$DSTACK_APP_ID"."$DSTACK_GATEWAY_DOMAIN
fi

echo "----------------------------------------------"
echo "Script execution completed"
echo "----------------------------------------------"
"#;

/// Get the default app_compose configuration for dstack deployments.
///
/// This provides sensible defaults that can be merged with user-provided
/// values. User values override these defaults.
pub fn get_default_app_compose() -> Value {
    json!({
        "allowed_envs": [],
        "docker_compose_file": "",
        "features": ["kms", "tproxy-net"],
        "gateway_enabled": true,
        "kms_enabled": true,
        "local_key_provider_enabled": false,
        "manifest_version": 2,
        "name": "",
        "no_instance_id": false,
        "pre_launch_script": DEFAULT_PRE_LAUNCH_SCRIPT,
        "public_logs": true,
        "public_sysinfo": true,
        "public_tcbinfo": true,
        "runner": "docker-compose",
        "secure_time": false,
        "storage_fs": "zfs",
        "tproxy_enabled": true
    })
}

/// Merge two JSON values, with overlay values overriding base values.
///
/// For objects, keys from overlay are inserted into base, overwriting
/// any existing values. For non-objects, overlay completely replaces base.
pub fn merge_json(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Object(base_map), Value::Object(overlay_map)) => {
            for (key, value) in overlay_map {
                base_map.insert(key.clone(), value.clone());
            }
        }
        (base, overlay) => *base = overlay.clone(),
    }
}

/// Merge a user-provided app_compose with default values.
///
/// This function allows users to provide only the fields they care about
/// (typically `docker_compose_file` and `allowed_envs`) and get a complete
/// app_compose configuration with all required default fields filled in.
///
/// User-provided values override defaults.
///
/// # Example
///
/// ```
/// use serde_json::json;
/// use atls_core::dstack::merge_with_default_app_compose;
///
/// let user_compose = json!({
///     "docker_compose_file": "services:\n  app:\n    image: myapp:latest",
///     "allowed_envs": ["API_KEY", "SECRET_TOKEN"]
/// });
///
/// let full_compose = merge_with_default_app_compose(&user_compose);
///
/// // User values are preserved
/// assert_eq!(full_compose["allowed_envs"], json!(["API_KEY", "SECRET_TOKEN"]));
///
/// // Default values are filled in
/// assert_eq!(full_compose["runner"], "docker-compose");
/// ```
pub fn merge_with_default_app_compose(user_compose: &Value) -> Value {
    let mut default = get_default_app_compose();
    merge_json(&mut default, user_compose);
    default
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_app_compose_has_required_fields() {
        let compose = get_default_app_compose();
        assert!(compose.get("allowed_envs").is_some());
        assert!(compose.get("docker_compose_file").is_some());
        assert!(compose.get("features").is_some());
        assert!(compose.get("runner").is_some());
    }

    #[test]
    fn test_merge_json_user_overrides_defaults() {
        let mut base = json!({
            "allowed_envs": [],
            "docker_compose_file": "",
            "features": ["kms"]
        });

        let overlay = json!({
            "docker_compose_file": "my-compose.yml",
            "allowed_envs": ["AUTH_TOKEN"]
        });

        merge_json(&mut base, &overlay);

        assert_eq!(base["docker_compose_file"], "my-compose.yml");
        assert_eq!(base["allowed_envs"], json!(["AUTH_TOKEN"]));
        // Features should remain unchanged (not in overlay)
        assert_eq!(base["features"], json!(["kms"]));
    }

    #[test]
    fn test_merge_json_adds_new_fields() {
        let mut base = json!({
            "existing": "value"
        });

        let overlay = json!({
            "new_field": "new_value"
        });

        merge_json(&mut base, &overlay);

        assert_eq!(base["existing"], "value");
        assert_eq!(base["new_field"], "new_value");
    }

    #[test]
    fn test_merge_json_non_object_replaces() {
        let mut base = json!("string");
        let overlay = json!("new_string");

        merge_json(&mut base, &overlay);

        assert_eq!(base, json!("new_string"));
    }

    #[test]
    fn test_merge_with_default_app_compose() {
        let user_compose = json!({
            "docker_compose_file": "services:\n  app:\n    image: test",
            "allowed_envs": ["MY_SECRET"]
        });

        let full = merge_with_default_app_compose(&user_compose);

        // User values are preserved
        assert_eq!(full["docker_compose_file"], "services:\n  app:\n    image: test");
        assert_eq!(full["allowed_envs"], json!(["MY_SECRET"]));

        // Defaults are filled in
        assert_eq!(full["runner"], "docker-compose");
        assert_eq!(full["manifest_version"], 2);
        assert!(full.get("pre_launch_script").is_some());
    }
}
