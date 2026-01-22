# aTLS Toolkit

Attested TLS for the modern web. This toolkit delivers verified TLS connections to Trusted Execution Environments (TEEs) from browsers (via WASM) and Node.js.

---

# 1. Project Overview & Quickstart

## Key Features
- Multi-platform: native bindings for Node.js, WASM for browsers, and a Rust core for direct integration.
- Configurable policy engine: enforce TCB levels, measurements, advisory IDs.
- Supported TEEs: Intel TDX today; AMD SEV-SNP planned.

---

# 2. Architecture & Data Flow

Browsers lack raw TCP sockets and attestation primitives. The toolkit uses WebSocket/WebTransport tunnels to work around these limitations.

1. **Handshake:** WASM client completes TLS 1.3 over a WebSocket connection.
2. **Quote Fetch:** Client issues an HTTP request to fetch the hardware quote.
3. **Verification:** `atls-core` validates the quote against the TLS certificate and user policy.

---

# 3. Component Guide

## `core/`
- `atls_connect`: Handshake + verification over a generic async byte stream.
- `AtlsVerifier` trait: Extensible verification interface for different TEE types.
- `DstackTdxPolicy`: Configures TDX verification including bootchain, app compose, and TCB status.

## `node/`
- `createAtlsFetch(...)`: Drop-in fetch replacement for Node.js applications.
- `createAtlsAgent(...)`: Custom HTTPS agent for use with existing HTTP clients.
- Works with AI SDKs (OpenAI, Vercel AI SDK) via fetch override.

Example:
```javascript
import { createAtlsFetch } from "atls-node";

const fetch = createAtlsFetch({
  target: "secure-enclave.com",
  policy: { type: "dstack_tdx", /* ... */ },
  onAttestation: (att) => console.log("TEE:", att.teeType)
});

const response = await fetch("/v1/chat/completions", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ model: "gpt", messages: [...] })
});

console.log(response.attestation); // { trusted: true, teeType: "tdx", ... }
```

## `wasm/`
- `AtlsHttp`: HTTP client over attested TLS with chunked transfer encoding support.
- `AttestedStream`: Low-level attested TLS stream for custom protocols.
- `createAtlsFetch(...)`: Fetch-compatible API for browser applications.

Example:
```javascript
import { createAtlsFetch } from "./pkg/atls-fetch.js";

const fetch = createAtlsFetch({
  proxyUrl: "ws://127.0.0.1:9000",
  targetHost: "secure-enclave.com",
  onAttestation: (att) => console.log("TEE:", att.teeType)
});

const response = await fetch("/v1/chat/completions", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ model: "gpt", messages: [...] })
});

// Streaming works (chunked encoding handled in WASM)
for await (const chunk of response.body) { /* ... */ }
console.log(response.attestation); // { trusted: true, teeType: "Tdx", ... }
```

## Additional Directories
- `python/`: PyO3 bindings with async helpers.
- `server-examples/`: Reference aTLS servers for TDX/SNP (coming soon).
- `docs/`: Design notes, specs, and task tracking.

## Binding status
- Node.js: functional; provides `createAtlsFetch` and `createAtlsAgent` via native NAPI bindings.
- WASM: functional; provides `AtlsHttp`, `AttestedStream`, and `createAtlsFetch`.
- Python: scaffolding in progress (`python/README.md`) with planned async API parity once the core pieces stabilize.

---

# 4. Policy Configuration

Policies describe what constitutes an acceptable attestation. The `atls-core` API (and each binding) consumes a `Policy` enum with the following shape:

```json
{
  "type": "dstack_tdx",
  "allowed_tcb_status": ["UpToDate", "SWHardeningNeeded"],
  "expected_bootchain": {
    "mrtd": "hex...",
    "rtmr0": "hex...",
    "rtmr1": "hex...",
    "rtmr2": "hex..."
  },
  "app_compose": {
    "runner": "docker-compose",
    "docker_compose_file": "..."
  },
  "os_image_hash": "hex...",
  "pccs_url": "https://pccs.phala.network/tdx/certification/v4"
}
```

| Field | Purpose |
| --- | --- |
| `type` | Chooses the verifier backend (`dstack_tdx`). |
| `allowed_tcb_status` | Acceptable TCB status strings (e.g., `UpToDate`, `SWHardeningNeeded`). |
| `expected_bootchain` | Expected MRTD and RTMR0-2 measurements for bootchain verification. |
| `app_compose` | Expected application compose configuration (hash verified). |
| `os_image_hash` | Expected OS image hash (SHA256). |
| `pccs_url` | Intel PCCS URL for collateral fetching. |

Verification flow with a policy:
1. Perform TLS handshake and capture server certificate.
2. Fetch TDX quote from server via `/tdx_quote` endpoint.
3. Verify DCAP quote signature using Intel PCS collateral.
4. Check TCB status is in `allowed_tcb_status`.
5. Verify certificate is bound in the event log.
6. Replay event log to verify RTMR3.
7. If configured, verify bootchain (MRTD, RTMR0-2), app compose hash, and OS image hash.

---

# 5. Protocol Specification

### Step 1: TLS Handshake
- TLS 1.3 with a promiscuous verifier. The certificate is accepted temporarily and recorded.

### Step 2: Quote Retrieval
Client sends an HTTP POST over the established TLS channel:
```http
POST /tdx_quote HTTP/1.1
Host: localhost
Content-Type: application/json
{
  "report_data": "<hex_nonce>"
}
```

Server responds:
```json
{
  "success": true,
  "quote": {
    "quote": "<hex_tdx_quote>",
    "event_log": [...]
  },
  "collateral": { ... }
}
```

### Step 3: Verification
1. Validate the quote signature using Intel PCCS collateral (`dcap-qvl` flow).
2. Ensure `report_data` equals the client nonce (freshness).
3. Recompute RTMR3 by replaying every event log entry in order and ensure the final digest matches the quote.
4. During that replay, locate the TLS key binding event (contains the certificate pubkey hash) to prove the attested workload owns the negotiated TLS key.

---

# Development Reference

## Directory Structure
- `core/`: Verification + policy (Rust).
- `node/`: Node.js bindings (NAPI-RS).
- `wasm/`: Browser bindings (WASM).
- `server-examples/`: Forthcoming reference TEEs.

## Build Commands

| Command | Description |
| --- | --- |
| `make test` | Run Rust unit tests for core. |
| `make test-wasm` | Check build for the `wasm32` target. |
| `make build-wasm` | Compile the WASM package into `pkg/`. |

## Troubleshooting WASM Builds
- Errors like `rust-lld: error: unknown file type` typically mean LLVM/Clang lacks `wasm32` support.
- On macOS, run `make setup-wasm` to install a compatible LLVM via Homebrew, then re-run `make build-wasm`.
