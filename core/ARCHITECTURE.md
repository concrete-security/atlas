# aTLS Core Architecture

This document describes the architecture of the `atls-core` crate, designed for contributors who want to understand the design or extend it with new TEE verifiers.

## Overview

aTLS (attested TLS) enables clients to verify that a TLS server is running inside a Trusted Execution Environment (TEE). The core crate provides:

- **High-level API**: One-shot `atls_connect()` for easy integration
- **Low-level API**: `AtlsVerifier` trait for custom TLS handling
- **Extensible design**: Add new TEE types by implementing traits and adding enum variants

## Design Philosophy

1. **Trait-based abstractions** - `AtlsVerifier` and `IntoVerifier` traits enable extensibility without modifying core logic
2. **Enum-based polymorphism** - `Policy`, `Verifier`, and `Report` enums provide type-safe runtime dispatch
3. **Policy-driven configuration** - JSON-serializable policies make configuration flexible and portable
4. **Platform abstraction** - Conditional compilation supports both native (tokio) and WASM (futures) targets

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                       High-Level API                            │
│    atls_connect(stream, server_name, policy, alpn)            │
│                                                                 │
│    1. TLS handshake with CA verification                       │
│    2. Capture peer certificate                                  │
│    3. Convert policy to verifier                                │
│    4. Run attestation verification                              │
│    5. Return (TlsStream, Report)                                │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                          Policy                                 │
│  ┌───────────────┐                                             │
│  │  DstackTdx    │─────▶ into_verifier() ─────▶ Verifier       │
│  │  (+ future)   │                                             │
│  └───────────────┘                                             │
│                                                                 │
│  Serializable with serde - load from JSON config files         │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Verifier                                │
│  ┌─────────────────────┐                                       │
│  │ DstackTDXVerifier   │─────▶ verify(stream, cert, hostname)  │
│  │ (+ future verifiers)│                                       │
│  └─────────────────────┘                                       │
│                                                                 │
│  Implements AtlsVerifier trait                                 │
│  Performs TEE-specific attestation verification                 │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                          Report                                 │
│  ┌───────────────┐                                             │
│  │ Tdx(...)      │  ← Contains dcap_qvl::VerifiedReport        │
│  │ (+ future)    │                                             │
│  └───────────────┘                                             │
│                                                                 │
│  Unified return type preserving TEE-specific details           │
└─────────────────────────────────────────────────────────────────┘
```

## Core Abstractions

### AtlsVerifier Trait

The core interface for attestation verification:

```rust
pub trait AtlsVerifier: Send + Sync {
    fn verify<S>(
        &self,
        stream: &mut S,       // TLS stream for quote fetching
        peer_cert: &[u8],     // Server's TLS certificate (DER)
        hostname: &str,       // Server hostname
    ) -> impl Future<Output = Result<Report, AtlsVerificationError>> + Send
    where
        S: AsyncByteStream;
}
```

### IntoVerifier Trait

Converts configuration/policy types into concrete verifiers:

```rust
pub trait IntoVerifier {
    type Verifier: AtlsVerifier;
    fn into_verifier(self) -> Result<Self::Verifier, AtlsVerificationError>;
}
```

### Policy Enum

Top-level configuration that selects and configures a verifier:

```rust
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Policy {
    #[serde(rename = "dstack_tdx")]
    DstackTdx(DstackTdxPolicy),
    // Future: Sgx(SgxPolicy), Sev(SevPolicy), etc.
}
```

### Verifier Enum

Wraps all concrete verifier implementations:

```rust
pub enum Verifier {
    DstackTdx(DstackTDXVerifier),
    // Future: Sgx(SgxVerifier), Sev(SevVerifier), etc.
}
```

### Report Enum

Unified return type containing TEE-specific attestation data:

```rust
pub enum Report {
    Tdx(VerifiedReport),
    // Future: Sgx(SgxReport), Sev(SevReport), etc.
}
```

## Verification Flow

When `atls_connect()` is called:

1. **TLS Handshake** - Establish TLS connection using webpki-roots CA bundle
2. **Certificate Capture** - Extract server's leaf certificate (DER-encoded)
3. **Policy → Verifier** - Call `policy.into_verifier()` to create the verifier
4. **Attestation** - Call `verifier.verify(stream, cert, hostname)`:
   - Fetch attestation quote from server (e.g., HTTP POST to `/tdx_quote`)
   - Verify quote cryptographically (e.g., Intel DCAP verification)
   - Verify certificate binding (cert hash in event log)
   - Verify measurements (bootchain, app config, OS image)
5. **Return** - Return `(TlsStream, Report)` for continued communication

## Module Structure

```
core/src/
├── lib.rs              # Public API re-exports
├── connect.rs          # atls_connect(), tls_handshake()
├── verifier.rs         # AtlsVerifier trait, Report/Verifier enums
├── policy.rs           # Policy enum
├── error.rs            # AtlsVerificationError
│
├── dstack/             # DStack TDX implementation
│   ├── mod.rs          # Re-exports
│   ├── verifier.rs     # DstackTDXVerifier (AtlsVerifier impl)
│   ├── config.rs       # DstackTDXVerifierConfig, Builder
│   ├── policy.rs       # DstackTdxPolicy (IntoVerifier impl)
│   └── compose_hash.rs # Deterministic app config hashing
│
└── tdx/                # Generic TDX types (shared across TDX verifiers)
    ├── mod.rs          # Re-exports
    └── config.rs       # ExpectedBootchain, TCB_STATUS_LIST
```

## Extending aTLS: Adding a New TEE Verifier

Follow these steps to add support for a new TEE (e.g., SGX, SEV-SNP).

### Step 1: Create Module Structure

```
core/src/
└── my_tee/
    ├── mod.rs
    ├── verifier.rs
    ├── config.rs
    └── policy.rs
```

### Step 2: Define Your Report Type

Add a variant to the `Report` enum in `verifier.rs`:

```rust
pub enum Report {
    Tdx(VerifiedReport),
    MyTee(MyTeeReport),  // Add your variant
}

impl Report {
    pub fn as_my_tee(&self) -> Option<&MyTeeReport> {
        match self {
            Report::MyTee(r) => Some(r),
            _ => None,
        }
    }
}
```

### Step 3: Implement AtlsVerifier

Create your verifier in `my_tee/verifier.rs`:

```rust
use crate::error::AtlsVerificationError;
use crate::verifier::{AsyncByteStream, AtlsVerifier, Report};

pub struct MyTeeVerifier {
    config: MyTeeVerifierConfig,
}

// Native implementation (tokio)
#[cfg(not(target_arch = "wasm32"))]
impl AtlsVerifier for MyTeeVerifier {
    async fn verify<S>(
        &self,
        stream: &mut S,
        peer_cert: &[u8],
        hostname: &str,
    ) -> Result<Report, AtlsVerificationError>
    where
        S: AsyncByteStream,
    {
        // 1. Fetch attestation evidence from server
        let evidence = self.fetch_evidence(stream, hostname).await?;

        // 2. Verify evidence cryptographically
        let report = self.verify_evidence(&evidence)?;

        // 3. Verify certificate binding
        self.verify_cert_binding(peer_cert, &evidence)?;

        // 4. Verify measurements against policy
        self.verify_measurements(&report)?;

        Ok(Report::MyTee(report))
    }
}

// WASM implementation (futures) - same logic, different trait bounds
#[cfg(target_arch = "wasm32")]
impl AtlsVerifier for MyTeeVerifier {
    async fn verify<S>(
        &self,
        stream: &mut S,
        peer_cert: &[u8],
        hostname: &str,
    ) -> Result<Report, AtlsVerificationError>
    where
        S: AsyncByteStream,
    {
        // Same implementation as native
    }
}
```

### Step 4: Create Config and Builder

In `my_tee/config.rs`:

```rust
use crate::error::AtlsVerificationError;

#[derive(Debug, Clone)]
pub struct MyTeeVerifierConfig {
    pub expected_measurement: Option<String>,
    pub allowed_status: Vec<String>,
    // ... other config fields
}

pub struct MyTeeVerifierBuilder {
    config: MyTeeVerifierConfig,
}

impl MyTeeVerifierBuilder {
    pub fn new() -> Self {
        Self {
            config: MyTeeVerifierConfig::default(),
        }
    }

    pub fn expected_measurement(mut self, m: impl Into<String>) -> Self {
        self.config.expected_measurement = Some(m.into());
        self
    }

    pub fn build(self) -> Result<MyTeeVerifier, AtlsVerificationError> {
        // Validate config
        MyTeeVerifier::new(self.config)
    }
}
```

### Step 5: Create Policy Type

In `my_tee/policy.rs`:

```rust
use serde::{Deserialize, Serialize};
use crate::error::AtlsVerificationError;
use crate::verifier::IntoVerifier;
use super::{MyTeeVerifier, MyTeeVerifierConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyTeePolicy {
    pub expected_measurement: Option<String>,
    #[serde(default = "default_allowed_status")]
    pub allowed_status: Vec<String>,
}

fn default_allowed_status() -> Vec<String> {
    vec!["Valid".into()]
}

impl IntoVerifier for MyTeePolicy {
    type Verifier = MyTeeVerifier;

    fn into_verifier(self) -> Result<Self::Verifier, AtlsVerificationError> {
        let config = MyTeeVerifierConfig {
            expected_measurement: self.expected_measurement,
            allowed_status: self.allowed_status,
        };
        MyTeeVerifier::new(config)
    }
}
```

### Step 6: Add to Enums

**In `policy.rs`:**

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Policy {
    #[serde(rename = "dstack_tdx")]
    DstackTdx(DstackTdxPolicy),
    #[serde(rename = "my_tee")]
    MyTee(MyTeePolicy),  // Add variant
}

impl Policy {
    pub fn into_verifier(self) -> Result<Verifier, AtlsVerificationError> {
        match self {
            Policy::DstackTdx(p) => Ok(Verifier::DstackTdx(p.into_verifier()?)),
            Policy::MyTee(p) => Ok(Verifier::MyTee(p.into_verifier()?)),  // Add arm
        }
    }
}
```

**In `verifier.rs`:**

```rust
pub enum Verifier {
    DstackTdx(DstackTDXVerifier),
    MyTee(MyTeeVerifier),  // Add variant
}

impl AtlsVerifier for Verifier {
    async fn verify<S>(...) -> Result<Report, AtlsVerificationError>
    where S: AsyncByteStream {
        match self {
            Verifier::DstackTdx(v) => v.verify(stream, peer_cert, hostname).await,
            Verifier::MyTee(v) => v.verify(stream, peer_cert, hostname).await,  // Add arm
        }
    }
}
```

### Step 7: Re-export in lib.rs

```rust
pub mod my_tee;

pub use my_tee::{MyTeeVerifier, MyTeeVerifierBuilder, MyTeeVerifierConfig, MyTeePolicy};
```

## Platform Support

The crate supports both native (Linux/macOS/Windows) and WASM targets.

### Differences

| Aspect | Native | WASM |
|--------|--------|------|
| Async runtime | tokio | futures |
| I/O traits | `tokio::io::{AsyncRead, AsyncWrite}` | `futures::io::{AsyncRead, AsyncWrite}` |
| Send bounds | Required (`Send + Sync`) | Not required (single-threaded) |
| Time source | `std::time::SystemTime` | `js_sys::Date` |
| RNG | `rand::thread_rng()` | `rand::thread_rng()` (wasm-compatible) |

### Conditional Compilation Pattern

```rust
// Trait definition with platform-specific bounds
#[cfg(not(target_arch = "wasm32"))]
pub trait AtlsVerifier: Send + Sync {
    fn verify<S>(...) -> impl Future<...> + Send
    where S: AsyncByteStream;
}

#[cfg(target_arch = "wasm32")]
pub trait AtlsVerifier: Sync {
    fn verify<S>(...) -> impl Future<...>  // No Send bound
    where S: AsyncByteStream;
}

// AsyncByteStream trait alias
#[cfg(not(target_arch = "wasm32"))]
pub trait AsyncByteStream: AsyncRead + AsyncWrite + Unpin + Send {}

#[cfg(target_arch = "wasm32")]
pub trait AsyncByteStream: AsyncRead + AsyncWrite + Unpin {}  // No Send
```

When implementing a new verifier, provide both `#[cfg(not(target_arch = "wasm32"))]` and `#[cfg(target_arch = "wasm32")]` implementations of `AtlsVerifier`. The logic is typically identical; only the trait bounds differ.
