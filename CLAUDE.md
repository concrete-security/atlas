# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Atlas (`atlas-rs`) is a multi-platform Rust library implementing **Attested TLS (aTLS)** — a protocol for verifying that TLS servers run inside Trusted Execution Environments (TEEs), specifically Intel TDX via Dstack. It ships as three targets: a pure Rust core, Node.js bindings (NAPI-RS), and WebAssembly bindings for browsers.

## Build & Test Commands

All commands use the root `Makefile`. Rust workspace has 4 members: `core`, `wasm`, `wasm/proxy`, `node`.

```bash
# Build
make build              # Build native crates (excludes WASM)
make build-wasm         # Build WASM package (requires wasm-pack)
make build-node         # Build Node.js bindings (requires pnpm)
cargo build -p atlas-rs # Build core only
cargo build -p atlas-proxy # Build proxy only

# Test
make test               # Native Rust tests (core + proxy, excludes WASM)
make test-all           # All tests (native + WASM + Node)
make test-proxy         # Proxy tests only
make test-wasm          # Check WASM compiles for wasm32 target
make test-wasm-node     # WASM tests via wasm-pack in Node.js
make test-node          # Node.js binding tests (cd node && pnpm test)

# Single test
cargo test -p atlas-rs <test_name>
cargo test -p atlas-proxy <test_name>

# WASM setup (macOS)
make setup-wasm         # Installs LLVM with wasm32 support via Homebrew
```

CI runs on `main` pushes and PRs: `test-core` (+ wasm32 check), `test-proxy`, `test-wasm`, `test-node` (Node 20, pnpm 10).

## Architecture

### Workspace Crates

| Crate | Package | Purpose |
|-------|---------|---------|
| `core/` | `atlas-rs` | Core verification logic, policies, TLS handling |
| `node/` | `@concrete-security/atlas-node` | NAPI-RS bindings exposing `atlsConnect` → wrapped by `atls-fetch.js` |
| `wasm/` | `atlas-wasm` / `@concrete-security/atlas-wasm` | wasm-bindgen bindings for browsers (needs WebSocket proxy) |
| `wasm/proxy/` | `atlas-proxy` | WebSocket-to-TCP proxy for browser WASM clients |

### Core Design (trait-based + enum dispatch)

The verification pipeline: **Policy → Verifier → Report**

- `Policy` enum (serde-tagged JSON): selects TEE type and configuration
- `IntoVerifier` trait: converts policy into a concrete verifier
- `AtlsVerifier` trait: performs attestation verification (`verify` method)
- `Verifier` enum: runtime dispatch wrapper for all verifier implementations
- `Report` enum: unified return type with TEE-specific data

High-level API: `atls_connect(stream, server_name, policy, alpn)` — does TLS handshake, captures peer cert, runs attestation, returns `(TlsStream, Report)`.

### Platform Abstraction (Native vs WASM)

Code uses `#[cfg(target_arch = "wasm32")]` throughout:
- **Native**: `tokio` runtime, `tokio::io::{AsyncRead, AsyncWrite}`, `Send + Sync` bounds, `aws_lc_rs` crypto
- **WASM**: `futures` runtime, `futures::io::{AsyncRead, AsyncWrite}`, no `Send` bound, `ring` crypto

When implementing a new verifier, provide both `#[cfg]` variants — logic is identical, only trait bounds differ.

### Key Source Files

- `core/src/connect.rs` — `atls_connect()`, TLS handshake
- `core/src/verifier.rs` — `AtlsVerifier` trait, `Report`/`Verifier` enums
- `core/src/policy.rs` — `Policy` enum
- `core/src/dstack/verifier.rs` — DStack TDX verification implementation
- `core/src/dstack/config.rs` — `DstackTDXVerifierConfig`, Builder pattern
- `core/src/dstack/compose_hash.rs` — Deterministic app config hashing
- `node/atls-fetch.js` — User-facing Node.js API
- `node/src/lib.rs` — NAPI-RS bindings

### Adding a New TEE Verifier

1. Create `core/src/<tee>/` with `config.rs`, `policy.rs`, `verifier.rs`
2. Implement `IntoVerifier` for the policy and `AtlsVerifier` for the verifier
3. Add variants to `Policy`, `Verifier`, and `Report` enums
4. Re-export in `core/src/lib.rs`

See `core/ARCHITECTURE.md` for the full walkthrough.

## Version Management

```bash
node node/scripts/sync-versions.mjs <new-version>  # Syncs node/npm/ package.json files
```
Then manually update `core/Cargo.toml` and `wasm/package.json`. Do **not** manually edit `node/npm/` package files.

## Common Pitfalls

1. **WASM vs Native async**: Always check `target_arch` feature gates when modifying I/O logic. `core` uses `tokio` for native and `futures` for WASM.
2. **Bootchain measurements**: `MRTD` and `RTMR` values are hardware-dependent (CPU count, RAM). Hardcoded test hashes break if backend infrastructure changes.
3. **Proxy allowlist**: `atlas-proxy` rejects connections by default. Set `ATLS_PROXY_ALLOWLIST` env var during testing.
4. **Node.js builds require pnpm** (v10) and `@napi-rs/cli`.
5. **WASM builds on macOS** require LLVM with wasm32 support (`make setup-wasm`).
