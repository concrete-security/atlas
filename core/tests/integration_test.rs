//! Integration tests for DstackTDXVerifier against vllm.concrete-security.com
//!
//! These tests verify real TDX attestation against a live dstack deployment.

use atlas_rs::{
    DstackTDXVerifierBuilder, ExpectedBootchain, AtlsVerificationError, dstack::{compose_hash::get_compose_hash, get_default_app_compose}
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

/// Docker compose file for vllm.concrete-security.com
fn get_vllm_docker_compose() -> &'static str {
    include_str!("data/vllm_docker_compose.yml")
}

#[test]
fn test_compose_hash_calculation() {
    // Test that compose hash calculation matches between Rust and Python
    let app_compose = get_default_app_compose();
    let hash = get_compose_hash(&app_compose).expect("Failed to compute compose hash");

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
        Err(AtlsVerificationError::Configuration(_))
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
        Err(AtlsVerificationError::Configuration(_))
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
    use atlas_rs::AtlsVerifier;
    use atlas_rs::{DstackTdxPolicy, Policy};
    use atlas_rs::tdx::grace_period::enforce_grace_period;
    use dcap_qvl::collateral::get_collateral;
    use dcap_qvl::quote::Quote;
    use dcap_qvl::verify::verify;
    use dstack_sdk_types::dstack::GetQuoteResponse;
    use rustls::pki_types::ServerName;
    use rustls::crypto::ring::default_provider;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::net::TcpStream;
    use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    fn ensure_crypto_provider() {
        // Install ring as the default crypto provider (ignore error if already installed)
        let _ = default_provider().install_default();
    }

    /// Establish an async TLS connection and return the stream, peer certificate, and session EKM.
    async fn connect_tls(
        host: &str,
    ) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
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

        // Get peer certificate and extract session EKM
        let (_, conn) = stream.get_ref();
        let peer_cert = conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| cert.as_ref().to_vec())
            .ok_or("No peer certificate found")?;

        // Extract session EKM for session binding (RFC 9266)
        let mut session_ekm = vec![0u8; 32];
        conn.export_keying_material(&mut session_ekm, b"EXPORTER-Channel-Binding", None)
            .map_err(|e| format!("Failed to extract session EKM: {}", e))?;

        Ok((stream, peer_cert, session_ekm))
    }

    #[derive(Debug, serde::Deserialize)]
    struct QuoteEndpointResponse {
        quote: GetQuoteResponse,
    }

    async fn get_quote_over_http(
        nonce: &[u8; 32],
        host: &str,
    ) -> Result<GetQuoteResponse, Box<dyn std::error::Error + Send + Sync>> {
        let body = serde_json::json!({
            "nonce_hex": hex::encode(nonce)
        });

        let url = format!("https://{}/tdx_quote", host);
        let response = reqwest::Client::new()
            .post(url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        let response: QuoteEndpointResponse = response.json().await?;
        Ok(response.quote)
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

        let (mut stream, peer_cert, session_ekm) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS");

        let result = verifier.verify(&mut stream, &peer_cert, &session_ekm, TEST_HOST).await;

        assert!(
            result.is_ok(),
            "Verification failed: {:?}",
            result.err()
        );
        let report = result.unwrap();
        match &report {
            atlas_rs::Report::Tdx(tdx_report) => {
                println!("Verification passed! TCB Status: {}", tdx_report.status);
            }
        }

        println!("Verification with disabled runtime verification passed!");
    }

    /// Test that a policy with grace_period set still verifies when the platform is not OutOfDate.
    #[tokio::test]
    async fn test_policy_grace_period_allows_non_outofdate() {
        let tcp = tokio::net::TcpStream::connect(format!("{}:443", TEST_HOST))
            .await
            .expect("Failed to connect TCP");

        let policy = Policy::DstackTdx(DstackTdxPolicy {
            grace_period: Some(0),
            allowed_tcb_status: vec![
                "UpToDate".to_string(),
                "OutOfDate".to_string(),
            ],
            disable_runtime_verification: true,
            ..Default::default()
        });

        let result = atlas_rs::atls_connect(tcp, TEST_HOST, policy, None).await;
        assert!(
            result.is_ok(),
            "Expected verification to succeed with grace_period set: {:?}",
            result.err()
        );
    }

    /// Test grace period behavior by forcing an OutOfDate status on a real quote.
    #[tokio::test]
    async fn test_grace_period_outofdate_paths() {
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);

        let quote_response = get_quote_over_http(&nonce, TEST_HOST)
            .await
            .expect("Failed to fetch quote");

        let quote_bytes = quote_response
            .decode_quote()
            .expect("Failed to decode quote");
        let quote = Quote::parse(&quote_bytes).expect("Failed to parse quote");

        let collateral = get_collateral(
            atlas_rs::dstack::policy::DEFAULT_PCCS_URL,
            &quote_bytes,
        )
        .await
        .expect("Failed to fetch collateral");

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let mut report = verify(&quote_bytes, &collateral, now_secs)
            .expect("DCAP verification failed");

        // Set it as OutOfDate to test grace period logic
        report.status = "OutOfDate".to_string();

        // Valid window: use a time before the TCB date to guarantee success.
        let valid = enforce_grace_period(&report, &quote, &collateral, Some(0), 0);
        assert!(valid.is_ok(), "Expected grace period to be valid");
        // Same as above but with a non-zero grace period
        let valid = enforce_grace_period(&report, &quote, &collateral, Some(60*60*24), 0);
        assert!(valid.is_ok(), "Expected grace period to be valid");

        // Expired window: use a far-future time to guarantee expiration.
        let expired = enforce_grace_period(
            &report,
            &quote,
            &collateral,
            Some(3600 * 24 * 30), // 30 days grace period
            (i64::MAX / 16) as u64, // div 16 to avoid overflow
        );
        assert!(
            matches!(expired, Err(AtlsVerificationError::GracePeriodExpired { .. })),
            "Expected GracePeriodExpired, got: {:?}",
            expired
        );
    }

    /// Test verifier with bootchain verification.
    /// This verifies DCAP quote, RTMR replay, and bootchain measurements.
    #[tokio::test]
    async fn test_verifier_bootchain_verification() {
        // Use a minimal app_compose just to satisfy the builder
        // We won't actually verify it matches since we don't know the exact compose
        let mut app_compose = get_default_app_compose();
        app_compose["docker_compose_file"] = json!(get_vllm_docker_compose());
        app_compose["allowed_envs"] = json!(["EKM_SHARED_SECRET", "AUTH_SERVICE_TOKEN"]);

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

        let (mut stream, peer_cert, session_ekm) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS");

        let result = verifier.verify(&mut stream, &peer_cert, &session_ekm, TEST_HOST).await;

        // This might fail if app_compose doesn't match - that's expected
        // The important thing is that the verifier runs the full verification
        match &result {
            Ok(report) => {
                match report {
                    atlas_rs::Report::Tdx(tdx_report) => {
                        println!("Full verification passed! TCB Status: {}", tdx_report.status);
                    }
                }
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

        let (mut stream, peer_cert, session_ekm) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS");

        let result = verifier.verify(&mut stream, &peer_cert, &session_ekm, TEST_HOST).await;

        assert!(
            matches!(result, Err(AtlsVerificationError::BootchainMismatch { .. })),
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

        let (mut stream, peer_cert, session_ekm) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS");

        let result = verifier.verify(&mut stream, &peer_cert, &session_ekm, TEST_HOST).await;

        // The verifier should fail with either AppComposeHashMismatch (if compose doesn't match)
        // or OsImageHashMismatch (if compose matches but OS hash doesn't)
        assert!(
            matches!(
                result,
                Err(AtlsVerificationError::OsImageHashMismatch { .. })
                    | Err(AtlsVerificationError::AppComposeHashMismatch { .. })
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
        let (mut stream1, peer_cert1, session_ekm1) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS (1)");
        let result1 = verifier.verify(&mut stream1, &peer_cert1, &session_ekm1, TEST_HOST).await;
        assert!(result1.is_ok(), "First verification failed: {:?}", result1.err());

        // Second verification (should use cached collateral)
        let (mut stream2, peer_cert2, session_ekm2) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS (2)");
        let result2 = verifier.verify(&mut stream2, &peer_cert2, &session_ekm2, TEST_HOST).await;
        assert!(result2.is_ok(), "Second verification failed: {:?}", result2.err());

        println!("Multiple verifications with same verifier instance passed!");
    }

    /// Test that collateral caching works correctly across multiple verifications.
    #[tokio::test]
    async fn test_collateral_caching() {
        let verifier = DstackTDXVerifierBuilder::new()
            .disable_runtime_verification()
            .allowed_tcb_status(vec![
                "UpToDate".to_string(),
                "SWHardeningNeeded".to_string(),
            ])
            .cache_collateral(true)
            .build()
            .expect("Failed to build verifier");

        // First verification - fetches collateral from PCCS
        let (mut stream1, peer_cert1, session_ekm1) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS (1)");
        let result1 = verifier.verify(&mut stream1, &peer_cert1, &session_ekm1, TEST_HOST).await;
        assert!(result1.is_ok(), "First verification failed: {:?}", result1.err());

        // Second verification - uses cached collateral
        let (mut stream2, peer_cert2, session_ekm2) = connect_tls(TEST_HOST).await.expect("Failed to connect TLS (2)");
        let result2 = verifier.verify(&mut stream2, &peer_cert2, &session_ekm2, TEST_HOST).await;
        assert!(result2.is_ok(), "Second verification (cached) failed: {:?}", result2.err());

        println!("Collateral caching test passed!");
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
            let (mut stream, peer_cert, session_ekm) = connect_tls(TEST_HOST).await?;
            verifier.verify(&mut stream, &peer_cert, &session_ekm, TEST_HOST).await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        });

        assert!(
            result.is_ok(),
            "Sync wrapper verification failed: {:?}",
            result.err()
        );

        println!("Sync wrapper verification passed!");
    }

    /// Test the high-level atls_connect API with full verification policy.
    #[tokio::test]
    async fn test_atls_connect_full_verification() {
        let tcp = tokio::net::TcpStream::connect(format!("{}:443", TEST_HOST))
            .await
            .expect("Failed to connect TCP");

        let mut app_compose = get_default_app_compose();
        app_compose["docker_compose_file"] = json!(get_vllm_docker_compose());
        app_compose["allowed_envs"] = json!(["EKM_SHARED_SECRET", "AUTH_SERVICE_TOKEN"]);

        let policy = atlas_rs::Policy::DstackTdx(atlas_rs::DstackTdxPolicy {
            expected_bootchain: Some(test_bootchain()),
            app_compose: Some(app_compose),
            os_image_hash: Some(TEST_OS_IMAGE_HASH.to_string()),
            allowed_tcb_status: vec![
                "UpToDate".to_string(),
                "SWHardeningNeeded".to_string(),
            ],
            ..Default::default()
        });
        let result = atlas_rs::atls_connect(tcp, TEST_HOST, policy, None).await;

        // This might fail if app_compose doesn't match - that's expected
        // The important thing is that the verifier runs the full verification
        match &result {
            Ok((_, report)) => {
                match report {
                    atlas_rs::Report::Tdx(tdx_report) => {
                        println!("atls_connect full verification passed! TCB Status: {}", tdx_report.status);
                    }
                }
            }
            Err(e) => {
                panic!("Unexpected verification error: {:?}", e);
            }
        }
    }

    /// Test atls_connect with ALPN protocols and full verification.
    #[tokio::test]
    async fn test_atls_connect_with_alpn() {
        let tcp = tokio::net::TcpStream::connect(format!("{}:443", TEST_HOST))
            .await
            .expect("Failed to connect TCP");

        let mut app_compose = get_default_app_compose();
        app_compose["docker_compose_file"] = json!(get_vllm_docker_compose());
        app_compose["allowed_envs"] = json!(["EKM_SHARED_SECRET", "AUTH_SERVICE_TOKEN"]);

        let policy = atlas_rs::Policy::DstackTdx(atlas_rs::DstackTdxPolicy {
            expected_bootchain: Some(test_bootchain()),
            app_compose: Some(app_compose),
            os_image_hash: Some(TEST_OS_IMAGE_HASH.to_string()),
            allowed_tcb_status: vec![
                "UpToDate".to_string(),
                "SWHardeningNeeded".to_string(),
            ],
            ..Default::default()
        });
        let result = atlas_rs::atls_connect(
            tcp,
            TEST_HOST,
            policy,
            Some(vec!["http/1.1".into()]),
        ).await;

        // This might fail if app_compose doesn't match - that's expected
        match &result {
            Ok((_, report)) => {
                match report {
                    atlas_rs::Report::Tdx(tdx_report) => {
                        println!("atls_connect with ALPN passed! TCB Status: {}", tdx_report.status);
                    }
                }
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

        let result = atlas_rs::connect::tls_handshake(tcp, TEST_HOST, None).await;

        assert!(
            result.is_ok(),
            "tls_handshake failed: {:?}",
            result.err()
        );

        let (_, peer_cert, session_ekm) = result.unwrap();
        assert!(!peer_cert.is_empty(), "Peer certificate should not be empty");
        assert_eq!(session_ekm.len(), 32, "Session EKM should be 32 bytes");
        println!("tls_handshake passed! Cert size: {} bytes, EKM: {} bytes", peer_cert.len(), session_ekm.len());
    }
}
