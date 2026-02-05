# Atlas

Atlas is a library implementing an attested TLS (aTLS) protocol. It delivers verified TLS connections to Trusted Execution Environments (TEEs) from different platforms (Browsers/Wasm, Node.js, Rust).

> [!NOTE]
> Atlas is the library name, while aTLS refers to the attested TLS protocol.

---

## Overview

### Key Features
- **Multi-platform**: Native bindings for Node.js, WASM for browsers, and a Rust crate (native)
- **Configurable policy engine**: Enforce TCB levels, bootchain measurements, and application configurations
- **Supported TEEs**: Intel TDX (AMD SEV-SNP planned)
- **Session binding**: Cryptographic binding of attestations to TLS sessions via EKM (RFC 9266)

### Quick Start

Choose your platform:
- **Node.js**: `npm install @concrete-security/atlas-node` → [See node/README.md](node/README.md)
- **Browser/WASM**: `npm install @concrete-security/atlas-wasm` → [See wasm/README.md](wasm/README.md)
- **Rust**: `cargo add atlas-rs` → [See core/README.md](core/README.md)

For protocol details, policy configuration, and security features, see [core/README.md](core/README.md).

---

## Documentation

- **[core/README.md](core/README.md)** - aTLS protocol documentation including policy configuration, security features, and protocol specification
- **[core/ARCHITECTURE.md](core/ARCHITECTURE.md)** - Architecture guide for contributors and extending aTLS
- **[core/BOOTCHAIN-VERIFICATION.md](core/BOOTCHAIN-VERIFICATION.md)** - Computing bootchain measurements for production deployments
- **[node/README.md](node/README.md)** - Node.js binding API reference and examples
- **[wasm/README.md](wasm/README.md)** - Browser/WASM binding API reference and setup
- **[wasm/proxy/README.md](wasm/proxy/README.md)** - WebSocket proxy configuration for browser deployments

---

## Development

### Directory Structure
- [core/](core/) - Rust library for attestation verification and policy enforcement
- [node/](node/) - Node.js bindings via NAPI-RS
- [wasm/](wasm/) - Browser bindings via WebAssembly

### Build Commands

See [Makefile](./Makefile).

For platform-specific build instructions, see [node/README.md](node/README.md) and [wasm/README.md](wasm/README.md).
