# atlas-rs

Rust library for attested TLS (aTLS) verification. Verify that TLS servers are running inside Trusted Execution Environments (TEEs) like Intel TDX before sending sensitive data.

**aTLS protocol documentation:** This document describes the core aTLS protocol, policy configuration, security features, and verification flow.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
atlas-rs = "0.1"
```

Or use `cargo add`:

```bash
cargo add atlas-rs
```

**Development/Latest:** To use the latest development version from GitHub:

```toml
[dependencies]
atlas-rs = { git = "https://github.com/concrete-security/atlas", branch = "main" }
```

## Quick Start

### Development Mode (Relaxed Verification)

For development and testing, use `DstackTdxPolicy::dev()` which accepts more TCB statuses but still verifies the TEE:

```rust
use atlas_rs::{atls_connect, Policy, DstackTdxPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tcp = tokio::net::TcpStream::connect("tee-server.example.com:443").await?;

    // Development policy - relaxed TCB status, no bootchain verification
    let policy = Policy::DstackTdx(DstackTdxPolicy::dev());

    let (mut tls_stream, report) = atls_connect(tcp, "tee-server.example.com", policy, None).await?;

    // Access attestation report
    match &report {
        atlas_rs::Report::Tdx(tdx_report) => {
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
use atlas_rs::{atls_connect, Policy, DstackTdxPolicy, ExpectedBootchain};
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
use atlas_rs::{atls_connect, Policy};

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
use atlas_rs::{DstackTDXVerifier, AtlsVerifier, ExpectedBootchain};
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
use atlas_rs::{Policy, DstackTdxPolicy, ExpectedBootchain};
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
use atlas_rs::{atls_connect, Policy, DstackTdxPolicy, AtlsVerificationError};

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

## Security Features

### Session Binding via EKM

aTLS binds attestations to specific TLS sessions using **Exported Keying Material (EKM)** per [RFC 5705](https://datatracker.ietf.org/doc/html/rfc5705), [RFC 8446 Section 7.5](https://datatracker.ietf.org/doc/html/rfc8446#section-7.5), and [RFC 9266](https://datatracker.ietf.org/doc/html/rfc9266). This prevents attestation relay attacks where an attacker (non-TEE) with a compromised private key could relay attestations across different TLS sessions.

**How It Works:**

1. After TLS handshake, both client and server extract a 32-byte session-specific EKM using the label `"EXPORTER-Channel-Binding"`
2. Client generates a random 32-byte nonce for freshness
3. Both parties compute `report_data = SHA512(nonce || session_ekm)`
4. Server generates a TDX quote with this computed `report_data`
5. Client verifies the quote, ensuring the `report_data` matches its own computation

Since the EKM is derived from the TLS session's master secret (unique per session), each attestation is cryptographically bound to its specific TLS connection. An attacker cannot relay an attestation from one session to another, even with access to the private key.

**Key Properties:**
- **Always enabled** - No configuration needed
- **Transparent** - Works automatically with all aTLS connections
- **Standards-based** - Uses RFC 9266 channel binding for TLS 1.3
- **Defense-in-depth** - Protects against key compromise scenarios

## Protocol Specification

### Step 1: TLS Handshake

TLS 1.3 handshake with a promiscuous verifier. The certificate is accepted temporarily and recorded for later verification.

### Step 2: EKM Extraction & Quote Retrieval

After TLS handshake, both client and server extract session EKM:

```rust
session_ekm = export_keying_material(32, "EXPORTER-Channel-Binding", None)
```

Client generates a 32-byte nonce and computes expected report_data:

```rust
nonce = random_bytes(32)
report_data = SHA512(nonce || session_ekm)
```

Client sends an HTTP POST over the established TLS channel:

```http
POST /tdx_quote HTTP/1.1
Host: localhost
Content-Type: application/json

{
  "nonce_hex": "<hex_nonce>"
}
```

Server extracts its own session EKM, computes the same `report_data = SHA512(nonce || server_ekm)`, and generates a quote with that report_data.

Server responds:

```json
{
  "success": true,
  "quote": {
    "quote": "<hex_tdx_quote>",
    "event_log": ["..."]
  },
  "...": "..."
}
```

### Step 3: Verification

1. Validate the quote signature using Intel PCCS collateral (DCAP verification flow)
2. Ensure `report_data` in the quote equals `SHA512(nonce || session_ekm)` (session binding + freshness)
3. Recompute RTMR3 by replaying every event log entry in order and ensure the final digest matches the quote
4. During that replay, locate the TLS key binding event (contains the certificate pubkey hash) to prove the attested workload owns the negotiated TLS key
5. Verify bootchain (MRTD, RTMR0-2), app compose hash, and OS image hash against policy

## TCB Status Values

TCB (Trusted Computing Base) status indicates the security posture of the TEE platform:

| Status | Meaning | Production Use |
|--------|---------|----------------|
| `UpToDate` | Platform is fully patched | ✅ Recommended |
| `SWHardeningNeeded` | Software hardening recommended but not critical | ⚠️ Acceptable with risk assessment |
| `ConfigurationNeeded` | Platform configuration changes recommended | ⚠️ Acceptable with risk assessment |
| `ConfigurationAndSWHardeningNeeded` | Both configuration and SW hardening needed | ⚠️ Use with caution |
| `OutOfDate` | Platform has known security vulnerabilities | ❌ Not recommended |
| `OutOfDateConfigurationNeeded` | Platform is out of date and needs reconfiguration | ❌ Not recommended |

Configure allowed statuses via `allowed_tcb_status` in your policy. For production, use `["UpToDate"]`. For development/testing, `DstackTdxPolicy::dev()` allows more permissive statuses.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Design overview and extension guide for contributors
- [BOOTCHAIN-VERIFICATION.md](BOOTCHAIN-VERIFICATION.md) - Computing bootchain measurements for production deployments

## Platform Support

- **Native** (Linux, macOS, Windows): Full support with tokio async I/O
- **WASM**: Browser support via futures async I/O (see [wasm/](../wasm/))
