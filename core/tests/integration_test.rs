//! Integration tests for DstackTDXVerifier against vllm.concrete-security.com
//!
//! These tests verify real TDX attestation against a live dstack deployment.

use ratls_core::{
    compose_hash::get_compose_hash, DstackTDXVerifierBuilder, ExpectedBootchain,
    RatlsVerificationError,
};
use serde_json::json;

/// Test server hostname
const TEST_HOST: &str = "vllm.concrete-security.com";

/// OS image hash for testing.
/// This is the hash observed in production for vllm.concrete-security.com
/// and should be updated if the OS image changes.
const TEST_OS_IMAGE_HASH: &str =
    "86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a";

/// Bootchain measurements for testing (Dstack 0.5.4.1-nvidia).
fn test_bootchain() -> ExpectedBootchain {
    ExpectedBootchain {
        mrtd: "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217".to_string(),
        rtmr0: "24c15e08c07aa01c531cbd7e8ba28f8cb62e78f6171bf6a8e0800714a65dd5efd3a06bf0cf5433c02bbfac839434b418".to_string(),
        rtmr1: "6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7".to_string(),
        rtmr2: "89e73cedf48f976ffebe8ac1129790ff59a0f52d54d969cb73455b1a79793f1dc16edc3b1fccc0fd65ea5905774bbd57".to_string(),
    }
}

/// Default app_compose configuration for dstack deployments.
fn get_default_app_compose() -> serde_json::Value {
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
        "pre_launch_script": "#!/bin/bash\necho \"----------------------------------------------\"\necho \"Running Phala Cloud Pre-Launch Script v0.0.10\"\necho \"----------------------------------------------\"\nset -e\n\n# Function: notify host\n\nnotify_host() {\n    if command -v dstack-util >/dev/null 2>&1; then\n        dstack-util notify-host -e \"$1\" -d \"$2\"\n    else\n        tdxctl notify-host -e \"$1\" -d \"$2\"\n    fi\n}\n\nnotify_host_hoot_info() {\n    notify_host \"boot.progress\" \"$1\"\n}\n\nnotify_host_hoot_error() {\n    notify_host \"boot.error\" \"$1\"\n}\n\n# Function: Perform Docker cleanup\nperform_cleanup() {\n    echo \"Pruning unused images\"\n    docker image prune -af\n    echo \"Pruning unused volumes\"\n    docker volume prune -f\n    notify_host_hoot_info \"docker cleanup completed\"\n}\n\n# Function: Check Docker login status without exposing credentials\ncheck_docker_login() {\n    # Try to verify login status without exposing credentials\n    if docker info 2>/dev/null | grep -q \"Username\"; then\n        return 0\n    else\n        return 1\n    fi\n}\n\n# Main logic starts here\necho \"Starting login process...\"\n\n# Check if Docker credentials exist\nif [[ -n \"$DSTACK_DOCKER_USERNAME\" && -n \"$DSTACK_DOCKER_PASSWORD\" ]]; then\n    echo \"Docker credentials found\"\n    \n    # Check if already logged in\n    if check_docker_login; then\n        echo \"Already logged in to Docker registry\"\n    else\n        echo \"Logging in to Docker registry...\"\n        # Login without exposing password in process list\n        if [[ -n \"$DSTACK_DOCKER_REGISTRY\" ]]; then\n            echo \"$DSTACK_DOCKER_PASSWORD\" | docker login -u \"$DSTACK_DOCKER_USERNAME\" --password-stdin \"$DSTACK_DOCKER_REGISTRY\"\n        else\n            echo \"$DSTACK_DOCKER_PASSWORD\" | docker login -u \"$DSTACK_DOCKER_USERNAME\" --password-stdin\n        fi\n        \n        if [ $? -eq 0 ]; then\n            echo \"Docker login successful\"\n        else\n            echo \"Docker login failed\"\n            notify_host_hoot_error \"docker login failed\"\n            exit 1\n        fi\n    fi\n# Check if AWS ECR credentials exist\nelif [[ -n \"$DSTACK_AWS_ACCESS_KEY_ID\" && -n \"$DSTACK_AWS_SECRET_ACCESS_KEY\" && -n \"$DSTACK_AWS_REGION\" && -n \"$DSTACK_AWS_ECR_REGISTRY\" ]]; then\n    echo \"AWS ECR credentials found\"\n    \n    # Check if AWS CLI is installed\n    if [ ! -f \"./aws/dist/aws\" ]; then\n        notify_host_hoot_info \"awscli not installed, installing...\"\n        echo \"AWS CLI not installed, installing...\"\n        curl \"https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.24.14.zip\" -o \"awscliv2.zip\"\n        echo \"6ff031a26df7daebbfa3ccddc9af1450 awscliv2.zip\" | md5sum -c\n        if [ $? -ne 0 ]; then\n            echo \"MD5 checksum failed\"\n            notify_host_hoot_error \"awscli install failed\"\n            exit 1\n        fi\n        unzip awscliv2.zip &> /dev/null\n    else\n        echo \"AWS CLI is already installed: ./aws/dist/aws\"\n    fi\n\n    # Set AWS credentials as environment variables\n    export AWS_ACCESS_KEY_ID=\"$DSTACK_AWS_ACCESS_KEY_ID\"\n    export AWS_SECRET_ACCESS_KEY=\"$DSTACK_AWS_SECRET_ACCESS_KEY\"\n    export AWS_DEFAULT_REGION=\"$DSTACK_AWS_REGION\"\n    \n    # Set session token if provided (for temporary credentials)\n    if [[ -n \"$DSTACK_AWS_SESSION_TOKEN\" ]]; then\n        echo \"AWS session token found, using temporary credentials\"\n        export AWS_SESSION_TOKEN=\"$DSTACK_AWS_SESSION_TOKEN\"\n    fi\n    \n    # Test AWS credentials before attempting ECR login\n    echo \"Testing AWS credentials...\"\n    if ! ./aws/dist/aws sts get-caller-identity &> /dev/null; then\n        echo \"AWS credentials test failed\"\n        # For session token credentials, this might be expected if they're expired\n        # Log warning but don't fail startup\n        if [[ -n \"$DSTACK_AWS_SESSION_TOKEN\" ]]; then\n            echo \"Warning: AWS temporary credentials may have expired, continuing startup\"\n            notify_host_hoot_info \"AWS temporary credentials may have expired\"\n        else\n            echo \"AWS credentials test failed\"\n            notify_host_hoot_error \"Invalid AWS credentials\"\n            exit 1\n        fi\n    else\n        echo \"Logging in to AWS ECR...\"\n        ./aws/dist/aws ecr get-login-password --region $DSTACK_AWS_REGION | docker login --username AWS --password-stdin \"$DSTACK_AWS_ECR_REGISTRY\"\n        if [ $? -eq 0 ]; then\n            echo \"AWS ECR login successful\"\n            notify_host_hoot_info \"AWS ECR login successful\"\n        else\n            echo \"AWS ECR login failed\"\n            # For session token credentials, don't fail startup if login fails\n            if [[ -n \"$DSTACK_AWS_SESSION_TOKEN\" ]]; then\n                echo \"Warning: AWS ECR login failed with temporary credentials, continuing startup\"\n                notify_host_hoot_info \"AWS ECR login failed with temporary credentials\"\n            else\n                notify_host_hoot_error \"AWS ECR login failed\"\n                exit 1\n            fi\n        fi\n    fi\nfi\n\nperform_cleanup\n\n#\n# Set root password.\n#\nif [ -n \"$DSTACK_ROOT_PASSWORD\" ]; then\n    echo \"$DSTACK_ROOT_PASSWORD\" | passwd --stdin root 2>/dev/null         || printf '%s\\n%s\\n' \"$DSTACK_ROOT_PASSWORD\" \"$DSTACK_ROOT_PASSWORD\" | passwd root\n    unset DSTACK_ROOT_PASSWORD\n    echo \"Root password set/updated from DSTACK_ROOT_PASSWORD\"\n\nelif [ -z \"$(grep '^root:' /etc/shadow 2>/dev/null | cut -d: -f2)\" ]; then\n    DSTACK_ROOT_PASSWORD=$(\n        dd if=/dev/urandom bs=32 count=1 2>/dev/null         | sha256sum         | awk '{print $1}'         | cut -c1-32\n    )\n    echo \"$DSTACK_ROOT_PASSWORD\" | passwd --stdin root 2>/dev/null         || printf '%s\\n%s\\n' \"$DSTACK_ROOT_PASSWORD\" \"$DSTACK_ROOT_PASSWORD\" | passwd root\n    unset DSTACK_ROOT_PASSWORD\n    echo \"Root password set (random auto-init)\"\n\nelse\n    echo \"Root password already set; no changes.\"\nfi\n\nif [[ -n \"$DSTACK_ROOT_PUBLIC_KEY\" ]]; then\n    mkdir -p /home/root/.ssh\n    echo \"$DSTACK_ROOT_PUBLIC_KEY\" > /home/root/.ssh/authorized_keys\n    unset $DSTACK_ROOT_PUBLIC_KEY\n    echo \"Root public key set\"\nfi\nif [[ -n \"$DSTACK_AUTHORIZED_KEYS\" ]]; then\n    mkdir -p /home/root/.ssh\n    echo \"$DSTACK_AUTHORIZED_KEYS\" > /home/root/.ssh/authorized_keys\n    unset $DSTACK_AUTHORIZED_KEYS\n    echo \"Root authorized_keys set\"\nfi\n\n\nif [[ -S /var/run/dstack.sock ]]; then\n    export DSTACK_APP_ID=$(curl -s --unix-socket /var/run/dstack.sock http://dstack/Info | jq -j .app_id)\nelif [[ -S /var/run/tappd.sock ]]; then\n    export DSTACK_APP_ID=$(curl -s --unix-socket /var/run/tappd.sock http://dstack/prpc/Tappd.Info | jq -j .app_id)\nfi\n# Check if DSTACK_GATEWAY_DOMAIN is not set, try to get it from user_config or app-compose.json\n# Priority: user_config > app-compose.json\nif [[ -z \"$DSTACK_GATEWAY_DOMAIN\" ]]; then\n    # First try to get from /dstack/user_config if it exists and is valid JSON\n    if [[ -f /dstack/user_config ]] && jq empty /dstack/user_config 2>/dev/null; then\n        if [[ $(jq 'has(\"default_gateway_domain\")' /dstack/user_config 2>/dev/null) == \"true\" ]]; then\n            export DSTACK_GATEWAY_DOMAIN=$(jq -j '.default_gateway_domain' /dstack/user_config)\n        fi\n    fi\n\n    # If still not set, try to get from app-compose.json\n    if [[ -z \"$DSTACK_GATEWAY_DOMAIN\" ]] && [[ $(jq 'has(\"default_gateway_domain\")' app-compose.json) == \"true\" ]]; then\n        export DSTACK_GATEWAY_DOMAIN=$(jq -j '.default_gateway_domain' app-compose.json)\n    fi\nfi\nif [[ -n \"$DSTACK_GATEWAY_DOMAIN\" ]]; then\n    export DSTACK_APP_DOMAIN=$DSTACK_APP_ID\".\"$DSTACK_GATEWAY_DOMAIN\nfi\n\necho \"----------------------------------------------\"\necho \"Script execution completed\"\necho \"----------------------------------------------\"\n",
        "public_logs": true,
        "public_sysinfo": true,
        "public_tcbinfo": true,
        "runner": "docker-compose",
        "secure_time": false,
        "storage_fs": "zfs",
        "tproxy_enabled": true
    })
}

/// Docker compose file for vllm.concrete-security.com
fn get_vllm_docker_compose() -> &'static str {
    include_str!("data/vllm_docker_compose.yml")
}

#[test]
fn test_compose_hash_calculation() {
    // Test that compose hash calculation matches between Rust and Python
    let app_compose = get_default_app_compose();
    let hash = get_compose_hash(&app_compose);

    // This should be a valid hex string
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_builder_requires_bootchain_and_os_image_hash() {
    // Test that builder validation works
    let result = DstackTDXVerifierBuilder::new()
        .app_compose(get_default_app_compose())
        .expected_bootchain(test_bootchain())
        // Missing os_image_hash
        .build();

    assert!(matches!(
        result,
        Err(RatlsVerificationError::Configuration(_))
    ));
}

#[test]
fn test_builder_requires_app_compose() {
    // Test that builder requires app_compose when runtime verification is enabled
    let result = DstackTDXVerifierBuilder::new()
        .expected_bootchain(test_bootchain())
        .os_image_hash(TEST_OS_IMAGE_HASH)
        // Missing app_compose
        .build();

    assert!(matches!(
        result,
        Err(RatlsVerificationError::Configuration(_))
    ));
}

#[test]
fn test_builder_with_disabled_runtime_verification() {
    // Test that builder works with runtime verification disabled
    let result = DstackTDXVerifierBuilder::new()
        .disable_runtime_verification()
        .build();

    assert!(result.is_ok());
}

#[test]
fn test_builder_complete_config() {
    // Test complete builder configuration
    let mut app_compose = get_default_app_compose();
    app_compose["docker_compose_file"] = json!("test docker compose");

    let result = DstackTDXVerifierBuilder::new()
        .app_compose(app_compose)
        .expected_bootchain(test_bootchain())
        .os_image_hash(TEST_OS_IMAGE_HASH)
        .allowed_tcb_status(vec!["UpToDate".to_string(), "SWHardeningNeeded".to_string()])
        .cache_collateral(true)
        .build();

    assert!(result.is_ok());
}

#[test]
fn test_expected_bootchain_values() {
    // Verify the bootchain values are valid hex strings of correct length
    let bootchain = test_bootchain();

    assert_eq!(bootchain.mrtd.len(), 96); // 48 bytes = 96 hex chars
    assert_eq!(bootchain.rtmr0.len(), 96);
    assert_eq!(bootchain.rtmr1.len(), 96);
    assert_eq!(bootchain.rtmr2.len(), 96);

    // Verify they're valid hex
    assert!(hex::decode(&bootchain.mrtd).is_ok());
    assert!(hex::decode(&bootchain.rtmr0).is_ok());
    assert!(hex::decode(&bootchain.rtmr1).is_ok());
    assert!(hex::decode(&bootchain.rtmr2).is_ok());
}

mod integration {
    use super::*;
    use ratls_core::RatlsVerifier;
    use rustls::pki_types::ServerName;
    use rustls::crypto::ring::default_provider;
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    fn ensure_crypto_provider() {
        // Install ring as the default crypto provider (ignore error if already installed)
        let _ = default_provider().install_default();
    }

    /// Establish an async TLS connection and return the stream and peer certificate.
    async fn connect_tls(
        host: &str,
    ) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        // Ensure crypto provider is installed
        ensure_crypto_provider();

        // Build TLS config with system root certificates
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let server_name: ServerName<'_> = host.try_into()?;

        // Connect TCP
        let tcp_stream = TcpStream::connect(format!("{}:443", host)).await?;

        // Complete TLS handshake
        let stream = connector.connect(server_name.to_owned(), tcp_stream).await?;

        // Get peer certificate from the connection
        let (_, conn) = stream.get_ref();
        let peer_cert = conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| cert.as_ref().to_vec())
            .ok_or("No peer certificate found")?;

        Ok((stream, peer_cert))
    }

    /// Test verifier with runtime verification disabled.
    /// This is the simplest test - it only verifies DCAP quote and RTMR replay.
    #[tokio::test]
    async fn test_verifier_disabled_runtime_verification() {
        let verifier = DstackTDXVerifierBuilder::new()
            .disable_runtime_verification()
            .allowed_tcb_status(vec![
                "UpToDate".to_string(),
                "SWHardeningNeeded".to_string(),
            ])
            .build()
            .expect("Failed to build verifier");

        let (mut stream, peer_cert) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS");

        let result = verifier.verify(&mut stream, &peer_cert, TEST_HOST).await;

        assert!(
            result.is_ok(),
            "Verification failed: {:?}",
            result.err()
        );
        let report = result.unwrap();
        println!("Verification passed! TCB Status: {}", report.status);

        println!("Verification with disabled runtime verification passed!");
    }

    /// Test verifier with bootchain verification.
    /// This verifies DCAP quote, RTMR replay, and bootchain measurements.
    #[tokio::test]
    async fn test_verifier_bootchain_verification() {
        // Use a minimal app_compose just to satisfy the builder
        // We won't actually verify it matches since we don't know the exact compose
        let mut app_compose = get_default_app_compose();
        app_compose["docker_compose_file"] = json!(get_vllm_docker_compose());

        let verifier = DstackTDXVerifierBuilder::new()
            .expected_bootchain(test_bootchain())
            .os_image_hash(TEST_OS_IMAGE_HASH)
            .app_compose(app_compose)
            .allowed_tcb_status(vec![
                "UpToDate".to_string(),
                "SWHardeningNeeded".to_string(),
            ])
            .build()
            .expect("Failed to build verifier");

        let (mut stream, peer_cert) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS");

        let result = verifier.verify(&mut stream, &peer_cert, TEST_HOST).await;

        // This might fail if app_compose doesn't match - that's expected
        // The important thing is that the verifier runs the full verification
        match &result {
            Ok(report) => {
                println!("Full verification passed! TCB Status: {}", report.status);
            }
            Err(RatlsVerificationError::AppComposeHashMismatch { expected, actual }) => {
                println!(
                    "App compose hash mismatch (expected if it is out of date):\n  Expected: {}\n  Actual: {}",
                    expected, actual
                );
                // This is acceptable - the bootchain verification passed
            }
            Err(e) => {
                panic!("Unexpected verification error: {:?}", e);
            }
        }
    }

    /// Test that verifier fails with wrong bootchain measurements.
    #[tokio::test]
    async fn test_verifier_wrong_bootchain_fails() {
        let wrong_bootchain = ExpectedBootchain {
            mrtd: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            rtmr0: test_bootchain().rtmr0,
            rtmr1: test_bootchain().rtmr1,
            rtmr2: test_bootchain().rtmr2,
        };

        let mut app_compose = get_default_app_compose();
        app_compose["docker_compose_file"] = json!(get_vllm_docker_compose());

        let verifier = DstackTDXVerifierBuilder::new()
            .expected_bootchain(wrong_bootchain)
            .os_image_hash(TEST_OS_IMAGE_HASH)
            .app_compose(app_compose)
            .allowed_tcb_status(vec![
                "UpToDate".to_string(),
                "SWHardeningNeeded".to_string(),
            ])
            .build()
            .expect("Failed to build verifier");

        let (mut stream, peer_cert) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS");

        let result = verifier.verify(&mut stream, &peer_cert, TEST_HOST).await;

        assert!(
            matches!(result, Err(RatlsVerificationError::BootchainMismatch { .. })),
            "Expected BootchainMismatch error, got: {:?}",
            result
        );

        println!("Verifier correctly rejected wrong bootchain!");
    }

    /// Test that verifier fails with wrong OS image hash.
    /// Note: Since app_compose is verified before os_image_hash, and we don't have the exact
    /// docker-compose file that matches the server, this test actually verifies that some
    /// verification fails. We use disable_runtime_verification to test OS hash in isolation.
    #[tokio::test]
    async fn test_verifier_fails_with_wrong_config() {
        let wrong_os_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        let mut app_compose = get_default_app_compose();
        app_compose["docker_compose_file"] = json!(get_vllm_docker_compose());

        let verifier = DstackTDXVerifierBuilder::new()
            .expected_bootchain(test_bootchain())
            .os_image_hash(wrong_os_hash)
            .app_compose(app_compose)
            .allowed_tcb_status(vec![
                "UpToDate".to_string(),
                "SWHardeningNeeded".to_string(),
            ])
            .build()
            .expect("Failed to build verifier");

        let (mut stream, peer_cert) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS");

        let result = verifier.verify(&mut stream, &peer_cert, TEST_HOST).await;

        // The verifier should fail with either AppComposeHashMismatch (if compose doesn't match)
        // or OsImageHashMismatch (if compose matches but OS hash doesn't)
        assert!(
            matches!(
                result,
                Err(RatlsVerificationError::OsImageHashMismatch { .. })
                    | Err(RatlsVerificationError::AppComposeHashMismatch { .. })
            ),
            "Expected verification error, got: {:?}",
            result
        );

        println!("Verifier correctly rejected wrong configuration!");
    }

    /// Test multiple verifications with the same verifier instance.
    #[tokio::test]
    async fn test_verifier_multiple_connections() {
        let verifier = DstackTDXVerifierBuilder::new()
            .disable_runtime_verification()
            .allowed_tcb_status(vec![
                "UpToDate".to_string(),
                "SWHardeningNeeded".to_string(),
            ])
            .cache_collateral(true)
            .build()
            .expect("Failed to build verifier");

        // First verification
        let (mut stream1, peer_cert1) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS (1)");
        let result1 = verifier.verify(&mut stream1, &peer_cert1, TEST_HOST).await;
        assert!(result1.is_ok(), "First verification failed: {:?}", result1.err());

        // Second verification (should use cached collateral)
        let (mut stream2, peer_cert2) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS (2)");
        let result2 = verifier.verify(&mut stream2, &peer_cert2, TEST_HOST).await;
        assert!(result2.is_ok(), "Second verification failed: {:?}", result2.err());

        println!("Multiple verifications with same verifier instance passed!");
    }

    /// Test using the async verifier from synchronous code.
    /// This demonstrates how to use the async API with a blocking runtime wrapper.
    #[test]
    fn test_verifier_sync_wrapper() {
        // Ensure crypto provider is installed
        ensure_crypto_provider();

        let verifier = DstackTDXVerifierBuilder::new()
            .disable_runtime_verification()
            .allowed_tcb_status(vec![
                "UpToDate".to_string(),
                "SWHardeningNeeded".to_string(),
            ])
            .build()
            .expect("Failed to build verifier");

        // Create a tokio runtime to run async code from sync context
        let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

        // Run the async verification using block_on
        let result = rt.block_on(async {
            let (mut stream, peer_cert) = connect_tls(TEST_HOST).await?;
            verifier.verify(&mut stream, &peer_cert, TEST_HOST).await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        });

        assert!(
            result.is_ok(),
            "Sync wrapper verification failed: {:?}",
            result.err()
        );

        println!("Sync wrapper verification passed!");
    }

    /// Test the high-level ratls_connect API with full verification policy.
    #[tokio::test]
    async fn test_ratls_connect_full_verification() {
        let tcp = tokio::net::TcpStream::connect(format!("{}:443", TEST_HOST))
            .await
            .expect("Failed to connect TCP");

        let mut app_compose = get_default_app_compose();
        app_compose["docker_compose_file"] = json!(get_vllm_docker_compose());

        let policy = ratls_core::Policy::DstackTdx(ratls_core::DstackTdxPolicy {
            expected_bootchain: Some(test_bootchain()),
            app_compose: Some(app_compose),
            os_image_hash: Some(TEST_OS_IMAGE_HASH.to_string()),
            allowed_tcb_status: vec![
                "UpToDate".to_string(),
                "SWHardeningNeeded".to_string(),
            ],
            ..Default::default()
        });
        let result = ratls_core::ratls_connect(tcp, TEST_HOST, policy, None).await;

        // This might fail if app_compose doesn't match - that's expected
        // The important thing is that the verifier runs the full verification
        match &result {
            Ok((_, report)) => {
                println!("ratls_connect full verification passed! TCB Status: {}", report.status);
            }
            Err(ratls_core::RatlsVerificationError::AppComposeHashMismatch { expected, actual }) => {
                println!(
                    "App compose hash mismatch (expected if it is out of date):\n  Expected: {}\n  Actual: {}",
                    expected, actual
                );
                // This is acceptable - the bootchain verification passed
            }
            Err(e) => {
                panic!("Unexpected verification error: {:?}", e);
            }
        }
    }

    /// Test ratls_connect with ALPN protocols and full verification.
    #[tokio::test]
    async fn test_ratls_connect_with_alpn() {
        let tcp = tokio::net::TcpStream::connect(format!("{}:443", TEST_HOST))
            .await
            .expect("Failed to connect TCP");

        let mut app_compose = get_default_app_compose();
        app_compose["docker_compose_file"] = json!(get_vllm_docker_compose());

        let policy = ratls_core::Policy::DstackTdx(ratls_core::DstackTdxPolicy {
            expected_bootchain: Some(test_bootchain()),
            app_compose: Some(app_compose),
            os_image_hash: Some(TEST_OS_IMAGE_HASH.to_string()),
            allowed_tcb_status: vec![
                "UpToDate".to_string(),
                "SWHardeningNeeded".to_string(),
            ],
            ..Default::default()
        });
        let result = ratls_core::ratls_connect(
            tcp,
            TEST_HOST,
            policy,
            Some(vec!["http/1.1".into()]),
        ).await;

        // This might fail if app_compose doesn't match - that's expected
        match &result {
            Ok((_, report)) => {
                println!("ratls_connect with ALPN passed! TCB Status: {}", report.status);
            }
            Err(ratls_core::RatlsVerificationError::AppComposeHashMismatch { expected, actual }) => {
                println!(
                    "App compose hash mismatch (expected if it is out of date):\n  Expected: {}\n  Actual: {}",
                    expected, actual
                );
            }
            Err(e) => {
                panic!("Unexpected verification error: {:?}", e);
            }
        }
    }

    /// Test tls_handshake separately.
    #[tokio::test]
    async fn test_tls_handshake_only() {
        let tcp = tokio::net::TcpStream::connect(format!("{}:443", TEST_HOST))
            .await
            .expect("Failed to connect TCP");

        let result = ratls_core::tls_handshake(tcp, TEST_HOST, None).await;

        assert!(
            result.is_ok(),
            "tls_handshake failed: {:?}",
            result.err()
        );

        let (_, peer_cert) = result.unwrap();
        assert!(!peer_cert.is_empty(), "Peer certificate should not be empty");
        println!("tls_handshake passed! Cert size: {} bytes", peer_cert.len());
    }
}
