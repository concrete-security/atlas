# atlas-wasm

attested TLS (aTLS) connections for Wasm. Connect securely to Trusted Execution Environments (TEEs) from the browser.

> **For aTLS protocol details, policy configuration, and security features, see [core/README.md](../core/README.md)**

## Installation

```bash
npm install @concrete-security/atlas-wasm
```

The package includes prebuilt WASM binaries for browser use.

## Architecture

The WASM module handles **attested TLS + HTTP/1.1 protocol** (including chunked transfer encoding for streaming LLM responses).

```
Browser (atls-fetch.js)          WASM (atlas_wasm)           Proxy              TEE
        │                               │                       │                  │
        │──── AtlsHttp.connect ───────►│                       │                  │
        │                               │──── WebSocket ───────►│                  │
        │                               │                       │──── TCP ────────►│
        │                               │◄──── TLS handshake + attestation ───────►│
        │◄─── attestation result ───────│                       │                  │
        │                               │                       │                  │
        │──── http.fetch(method,...) ──►│──── HTTP/1.1 req ────►│──── raw ────────►│
        │◄─── {status,headers,body} ────│◄──── HTTP/1.1 res ────│◄──── raw ────────│
```

A proxy is required since the Browser/Wasm environment doesn't have a socket API. So we implement aTLS over a WebSocket-to-TCP tunnel.


## Building from Source

The npm package includes prebuilt WASM binaries. To build from source:

```bash
# From repo root
make build-wasm
```

**macOS note:** Requires Clang with WebAssembly target support (Apple's Xcode clang doesn't support WASM). The build process automatically detects and uses Homebrew's LLVM if available. If you haven't installed it yet:

```bash
make setup-wasm
make build-wasm
```

## API

### `createAtlsFetch(options)`

Fetch-compatible API (HTTP handling in Rust/WASM):

```javascript
import { init, createAtlsFetch } from "@concrete-security/atlas-wasm";

await init();

const fetch = createAtlsFetch({
  proxyUrl: "ws://127.0.0.1:9000",
  targetHost: "vllm.example.com",
  policy: { type: "dstack_tdx" },  // Required: verification policy
  onAttestation: (att) => console.log("TEE:", att.teeType)
});

// Use like regular fetch
const response = await fetch("/v1/chat/completions", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ model: "gpt", messages: [...] })
});

console.log(response.status);
console.log(response.attestation); // { trusted: true, teeType: "Tdx", ... }
```

### Low-level: `AtlsHttp`

HTTP client with streaming body support:

```javascript
import init, { AtlsHttp } from "@concrete-security/atlas-wasm";

await init();

const http = await AtlsHttp.connect(
  "ws://127.0.0.1:9000?target=vllm.example.com:443",
  "vllm.example.com"
);

console.log(http.attestation()); // { trusted, teeType, tcbStatus }

const result = await http.fetch("POST", "/v1/chat/completions", "vllm.example.com",
  [["Content-Type", "application/json"]],
  new TextEncoder().encode('{"model":"gpt"}')
);

// result.body is a ReadableStream (handles chunked encoding automatically)
const reader = result.body.getReader();
// ... stream response ...
```

### Lowest-level: `AttestedStream`

Direct access to the raw attested TLS stream (no HTTP handling):

```javascript
import init, { AttestedStream } from "@concrete-security/atlas-wasm";

await init();

const stream = await AttestedStream.connect(
  "ws://127.0.0.1:9000?target=vllm.example.com:443",
  "vllm.example.com"
);

console.log(stream.attestation()); // { trusted, teeType, tcbStatus }

await stream.send(new TextEncoder().encode("GET / HTTP/1.1\r\n\r\n"));
const reader = stream.readable.getReader();
// ... read raw response bytes ...
```

## Proxy

Browser deployments require a WebSocket-to-TCP proxy since browsers cannot make raw TCP connections.

**Quick Start:**

```bash
# Required: set allowlist for security
export ATLS_PROXY_ALLOWLIST="vllm.example.com:443,other.tee.com:443"
export ATLS_PROXY_LISTEN="127.0.0.1:9000"

cargo run -p atlas-proxy
```

**Key Points:**
- Proxy only forwards bytes (no TLS termination)
- All encryption and attestation verification happens in the browser
- Allowlist is required for security (prevents SSRF attacks)

For detailed configuration, deployment patterns, and security considerations, see [proxy/README.md](proxy/README.md).

## Demo

A minimal browser demo is in `demo/`:

```bash
# From repo root - starts proxy + serves demo
make demo-wasm

# Then open: http://localhost:8080/demo/minimal.html
```

The demo shows:
1. Connecting to a non-TEE server (google.com) fails attestation
2. Connecting to a real TEE server succeeds with valid attestation

## Policy Configuration

Policies control what attestations are accepted. Configure via the `policy` option:

```javascript
const fetch = createAtlsFetch({
  proxyUrl: "ws://127.0.0.1:9000",
  targetHost: "vllm.example.com",
  policy: {
    type: "dstack_tdx",
    allowed_tcb_status: ["UpToDate", "SWHardeningNeeded"],
    expected_bootchain: {
      mrtd: "b24d3b24...",
      rtmr0: "24c15e08...",
      rtmr1: "6e1afb74...",
      rtmr2: "89e73ced..."
    }
  }
})
```

For complete policy field descriptions and verification flow, see [core/README.md#policy-configuration](../core/README.md#policy-configuration).

## Protocol Details

Browser WASM bindings follow the same aTLS protocol as other platforms.

For detailed protocol specification and security features, see [core/README.md#protocol-specification](../core/README.md#protocol-specification).
