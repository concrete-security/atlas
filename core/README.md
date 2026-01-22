# atls-core

Rust library for attested TLS (aTLS) verification. Verify that TLS servers are running inside Trusted Execution Environments (TEEs) like Intel TDX before sending sensitive data.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
atls-core = { git = "https://github.com/concrete-security/ratls", branch = "main" }
tokio = { version = "1", features = ["full"] }
serde_json = "1"
```

## Quick Start

### Development Mode (Relaxed Verification)

For development and testing, use `DstackTdxPolicy::dev()` which accepts more TCB statuses but still verifies the TEE:

```rust
use atls_core::{atls_connect, Policy, DstackTdxPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tcp = tokio::net::TcpStream::connect("tee-server.example.com:443").await?;

    // Development policy - relaxed TCB status, no bootchain verification
    let policy = Policy::DstackTdx(DstackTdxPolicy::dev());

    let (mut tls_stream, report) = atls_connect(tcp, "tee-server.example.com", policy, None).await?;

    // Access attestation report
    match &report {
        atls_core::Report::Tdx(tdx_report) => {
            println!("TEE verified! TCB Status: {}", tdx_report.status);
        }
    }

    // Use tls_stream for subsequent requests...
    Ok(())
}
```

### Full Verification (Production)

For production, provide bootchain measurements and app configuration:

```rust
use atls_core::{atls_connect, Policy, DstackTdxPolicy, ExpectedBootchain};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tcp = tokio::net::TcpStream::connect("vllm.concrete-security.com:443").await?;

    // Full verification policy
    let policy = Policy::DstackTdx(DstackTdxPolicy {
        expected_bootchain: Some(ExpectedBootchain {
            mrtd: "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217".into(),
            rtmr0: "24c15e08c07aa01c531cbd7e8ba28f8cb62e78f6171bf6a8e0800714a65dd5efd3a06bf0cf5433c02bbfac839434b418".into(),
            rtmr1: "6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7".into(),
            rtmr2: "89e73cedf48f976ffebe8ac1129790ff59a0f52d54d969cb73455b1a79793f1dc16edc3b1fccc0fd65ea5905774bbd57".into(),
        }),
        os_image_hash: Some("86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a".into()),
        app_compose: Some(json!({
            "runner": "docker-compose",
            "docker_compose_file": "version: '3'\nservices:\n  vllm:\n    image: vllm/vllm-openai:latest\n    ..."
        })),
        allowed_tcb_status: vec!["UpToDate".into()],
        ..Default::default()
    });

    let (mut tls_stream, report) = atls_connect(tcp, "vllm.concrete-security.com", policy, None).await?;

    println!("TEE fully verified!");

    // Use tls_stream for API requests...
    Ok(())
}
```

### JSON Policy Configuration

Policies can be loaded from JSON files:

```rust
use atls_core::{atls_connect, Policy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load policy from JSON
    let policy_json = r#"{
        "type": "dstack_tdx",
        "allowed_tcb_status": ["UpToDate", "SWHardeningNeeded"],
        "expected_bootchain": {
            "mrtd": "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
            "rtmr0": "24c15e08c07aa01c531cbd7e8ba28f8cb62e78f6171bf6a8e0800714a65dd5efd3a06bf0cf5433c02bbfac839434b418",
            "rtmr1": "6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7",
            "rtmr2": "89e73cedf48f976ffebe8ac1129790ff59a0f52d54d969cb73455b1a79793f1dc16edc3b1fccc0fd65ea5905774bbd57"
        },
        "os_image_hash": "86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a",
        "app_compose": {
            "runner": "docker-compose",
            "docker_compose_file": "..."
        }
    }"#;

    let policy: Policy = serde_json::from_str(policy_json)?;

    let tcp = tokio::net::TcpStream::connect("tee-server.example.com:443").await?;
    let (tls_stream, report) = atls_connect(tcp, "tee-server.example.com", policy, None).await?;

    Ok(())
}
```

## Low-Level API

For custom TLS handling, use the `AtlsVerifier` trait directly:

```rust
use atls_core::{DstackTDXVerifier, AtlsVerifier, ExpectedBootchain};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = DstackTDXVerifier::builder()
        .app_compose(json!({
            "runner": "docker-compose",
            "docker_compose_file": "..."
        }))
        .expected_bootchain(ExpectedBootchain {
            mrtd: "b24d3b24...".into(),
            rtmr0: "24c15e08...".into(),
            rtmr1: "6e1afb74...".into(),
            rtmr2: "89e73ced...".into(),
        })
        .os_image_hash("86b18137...")
        .build()?;

    // Use with your own TLS stream
    // let report = verifier.verify(&mut tls_stream, &peer_cert, "hostname").await?;

    Ok(())
}
```

## Computing Bootchain Measurements

Bootchain measurements depend on hardware configuration (CPU count, memory, GPUs, etc.). You must compute measurements for your specific deployment.

See [BOOTCHAIN-VERIFICATION.md](BOOTCHAIN-VERIFICATION.md) for detailed instructions on:
- Understanding TDX measurement registers (MRTD, RTMR0-3)
- Computing measurements using `dstack-mr`
- Step-by-step reproducible build process

## Policy Configuration

Policy fields vary by verifier implementation. The `Policy` enum wraps implementation-specific policy types.

### DstackTdxPolicy

**By default, all runtime fields are required.** Missing any field will cause a configuration error unless `disable_runtime_verification` is set to `true`.

| Field | Description | Required |
|-------|-------------|----------|
| `expected_bootchain` | MRTD and RTMR0-2 measurements | Yes (unless disabled) |
| `os_image_hash` | SHA256 of Dstack image's sha256sum.txt | Yes (unless disabled) |
| `app_compose` | Expected application configuration | Yes (unless disabled) |
| `allowed_tcb_status` | Acceptable TCB statuses (e.g., `["UpToDate"]`) | Yes |
| `disable_runtime_verification` | Skip runtime checks (default: false) | No |
| `pccs_url` | Intel PCCS URL (defaults to Phala's) | No |
| `cache_collateral` | Cache Intel collateral (default: false) | No |

```rust
use atls_core::{Policy, DstackTdxPolicy, ExpectedBootchain};
use serde_json::json;

// Development policy - explicitly disables runtime verification
// (sets disable_runtime_verification: true internally)
let dev_policy = Policy::DstackTdx(DstackTdxPolicy::dev());

// Production policy - all runtime fields required
let prod_policy = Policy::DstackTdx(DstackTdxPolicy {
    expected_bootchain: Some(ExpectedBootchain {
        mrtd: "b24d3b24...".into(),
        rtmr0: "24c15e08...".into(),
        rtmr1: "6e1afb74...".into(),
        rtmr2: "89e73ced...".into(),
    }),
    os_image_hash: Some("86b18137...".into()),
    app_compose: Some(json!({
        "runner": "docker-compose",
        "docker_compose_file": "..."
    })),
    allowed_tcb_status: vec!["UpToDate".into()],
    ..Default::default()
});

// This will FAIL - missing runtime fields without disable_runtime_verification
let invalid_policy = Policy::DstackTdx(DstackTdxPolicy::default());
// invalid_policy.into_verifier() returns Err(Configuration(...))
```

## Error Handling

```rust
use atls_core::{atls_connect, Policy, DstackTdxPolicy, AtlsVerificationError};

async fn verify_tee() -> Result<(), AtlsVerificationError> {
    let tcp = tokio::net::TcpStream::connect("tee.example.com:443")
        .await
        .map_err(|e| AtlsVerificationError::Io(e.to_string()))?;

    let policy = Policy::DstackTdx(DstackTdxPolicy::dev());

    match atls_connect(tcp, "tee.example.com", policy, None).await {
        Ok((stream, report)) => {
            println!("Verification succeeded!");
            Ok(())
        }
        Err(AtlsVerificationError::BootchainMismatch { field, expected, actual }) => {
            eprintln!("Bootchain mismatch in {}: expected {}, got {}", field, expected, actual);
            Err(AtlsVerificationError::BootchainMismatch { field, expected, actual })
        }
        Err(AtlsVerificationError::TcbStatusNotAllowed { status, allowed }) => {
            eprintln!("TCB status {} not in allowed list {:?}", status, allowed);
            Err(AtlsVerificationError::TcbStatusNotAllowed { status, allowed })
        }
        Err(e) => Err(e),
    }
}
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Design overview and extension guide
- [BOOTCHAIN-VERIFICATION.md](BOOTCHAIN-VERIFICATION.md) - Computing bootchain measurements

## Platform Support

- **Native** (Linux, macOS, Windows): Uses tokio for async I/O
- **WASM**: Uses futures for async I/O (see `wasm/` crate)
