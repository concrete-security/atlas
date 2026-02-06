# AGENTS.md

## Repository Overview

**Atlas** (`atlas-rs`) is a multi-platform library for implementing **Attested TLS (aTLS)**. It allows clients to verify that a remote TLS server is running inside a specific Trusted Execution Environment (TEE), specifically Intel TDX via Dstack.

### Key Capabilities

1. **Attestation Verification:** Validates Intel TDX quotes using Intel DCAP.
2. **Session Binding:** Binds attestation to the TLS session using Exported Keying Material (EKM) to prevent relay attacks (RFC 9266).
3. **Policy Enforcement:** Verifies bootchain measurements (MRTD, RTMRs), OS image hashes, and application configuration (Docker Compose).
4. **Multi-Platform:**
* **Core:** Pure Rust library (`core/`).
* **Node.js:** Native bindings via NAPI-RS (`node/`).
* **Wasm/Browser:** WebAssembly bindings (`wasm/`) requiring a WebSocket proxy.



---

## Directory Structure

| Path | Component | Description |
| --- | --- | --- |
| `core/` | **Core Library** | Rust implementation of verification logic, policies, and TLS handling. |
| `core/src/dstack/` | **Dstack Verifier** | Specific implementation for verifying Dstack-based TEE deployments. |
| `node/` | **Node.js Bindings** | NAPI-RS bindings exposing `createAtlsFetch` and `createAtlsAgent`. |
| `wasm/` | **WASM Bindings** | Rust code compiled to WASM for browser usage. |
| `wasm/proxy/` | **WebSocket Proxy** | Rust binary (`atlas-proxy`) to tunnel browser WebSocket connections to TCP. |
| `scripts/` | **Scripts** | Version synchronization scripts (`sync-versions.mjs`). |

---

## Core Concepts & Terminology

* **aTLS (Attested TLS):** A protocol where the client verifies the server's TEE evidence *after* the TLS handshake but *before* sending sensitive data.
* **TDX (Trusted Domain Extensions):** Intel's Confidential Computing technology.
* **Dstack:** The supported TEE orchestrator/runtime.
* **Measurement Registers:**
* **MRTD:** Measurement of the initial TD firmware/memory.
* **RTMR0:** Virtual hardware environment/bios.
* **RTMR1:** Linux Kernel.
* **RTMR2:** Kernel command line & Initramfs.
* **RTMR3:** Runtime measurements (App Compose, TLS Cert, OS Image).


* **EKM (Exported Keying Material):** A cryptographic secret derived from the TLS master secret, unique to the session. Used to bind the TDX Quote to the TLS connection.
* **PCCS:** Provisioning Certificate Caching Service (Intel). Used to fetch verification collateral.

---

## Development Patterns

### 1. Verification Logic (`core/`)

The core logic resides in `core/src/verifier.rs` and `core/src/dstack/verifier.rs`.

* **Trait:** `AtlsVerifier` is the main trait. It has an async `verify` method.
* **Platform Abstraction:** Code is conditionally compiled for `tokio` (Native) vs `futures` (WASM).
* `#[cfg(not(target_arch = "wasm32"))]`: Requires `Send + Sync`.
* `#[cfg(target_arch = "wasm32")]`: `Send` is not required (single-threaded JS runtime).



### 2. Adding a New Verifier

To add a new TEE type (e.g., SEV-SNP):

1. Define configuration in `core/src/<tee>/config.rs`.
2. Implement `IntoVerifier` for the policy in `core/src/<tee>/policy.rs`.
3. Implement `AtlsVerifier` in `core/src/<tee>/verifier.rs`.
4. Register in `core/src/policy.rs` (`Policy` enum) and `core/src/verifier.rs` (`Verifier` and `Report` enums).

### 3. Node.js Bindings (`node/`)

* Uses `napi-rs`.
* Exposes `atlsConnect` which returns a raw TCP socket ID.
* `atls-fetch.js` wraps this socket in a Node `https.Agent`.
* **Constraint:** Ensure `package.json` versions sync with `Cargo.toml`.

### 4. Wasm Bindings (`wasm/`)

* Uses `wasm-bindgen`.
* **Networking:** Browsers cannot do raw TCP.
* Client uses `WsMeta` to connect to a local proxy.
* Proxy (`wasm/proxy`) converts WebSocket -> TCP to the TEE.
* TLS is end-to-end (Browser -> Proxy -> TEE). The proxy **cannot** decrypt traffic.



---

## Build & Test Commands

Use the `Makefile` in the root directory.

| Task | Command | Notes |
| --- | --- | --- |
| **Test All** | `make test-all` | Runs Core, Wasm (in Node), and Node binding tests. |
| **Build Core** | `cargo build -p atlas-rs` |  |
| **Build Node** | `make build-node` | Requires `pnpm`. |
| **Build Wasm** | `make build-wasm` | Requires `wasm-pack`. |
| **Build Proxy** | `cargo build -p atlas-proxy` |  |
| **Run Proxy** | `cargo run -p atlas-proxy` | Set `ATLS_PROXY_ALLOWLIST` env var first. |

---

## Critical Files for Context

* `core/ARCHITECTURE.md`: Detailed data flow and trait hierarchy.
* `core/BOOTCHAIN-VERIFICATION.md`: How to calculate expected hashes for `dstack`.
* `core/src/dstack/verifier.rs`: The actual implementation of the verification steps (Quote -> Event Log -> Bootchain -> App Config).
* `node/atls-fetch.js`: The user-facing API for Node.js.

## Version Management

When updating versions, do **not** manually edit `package.json` files in `node/npm/`.
Use the script:

```bash
node node/scripts/sync-versions.mjs <new-version>

```

Then update `core/Cargo.toml` and `wasm/package.json` manually.

## Common Pitfalls

1. **Bootchain Mismatch:** `MRTD` and `RTMR` values change based on hardware config (CPU count, RAM). Tests using hardcoded hashes will fail if the backend infrastructure changes.
2. **WASM vs Native Async:** `core` uses `tokio` traits for Native and `futures` traits for WASM. Always check `target_arch` feature gates when modifying I/O logic.
3. **Proxy Allowlist:** The `atlas-proxy` rejects connections by default. Always configure `ATLS_PROXY_ALLOWLIST` during testing.