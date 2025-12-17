# wasm (browser client)

WASM bindings for RA-TLS attested connections. The module performs TLS 1.3 inside WASM and uses WebSocket tunnels via a proxy.

## Architecture

The WASM module focuses on **attested TLS only**. HTTP handling is done in JavaScript for simplicity.

```
Browser (ratls-fetch.js)          WASM (ratls_wasm)           Proxy              TEE
        │                               │                       │                  │
        │──── AttestedStream.connect ──►│                       │                  │
        │                               │──── WebSocket ───────►│                  │
        │                               │                       │──── TCP ────────►│
        │                               │◄──── TLS handshake + attestation ───────►│
        │◄─── attestation result ───────│                       │                  │
        │                               │                       │                  │
        │──── stream.send(request) ────►│──── encrypted ───────►│──── raw ────────►│
        │◄─── stream.readable ──────────│◄──── encrypted ───────│◄──── raw ────────│
```

## Building

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

### `createRatlsFetch(options)`

Fetch-compatible API with HTTP handling in JavaScript:

```javascript
import { init, createRatlsFetch } from "./pkg/ratls-fetch.js";

await init();

const fetch = createRatlsFetch({
  proxyUrl: "ws://127.0.0.1:9000",
  targetHost: "vllm.example.com",
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

### Low-level: `AttestedStream`

Direct access to the attested TLS stream:

```javascript
import init, { AttestedStream } from "./pkg/ratls_wasm.js";

await init();

const stream = await AttestedStream.connect(
  "ws://127.0.0.1:9000?target=vllm.example.com:443",
  "vllm.example.com"
);

console.log(stream.attestation()); // { trusted, teeType, tcbStatus }

await stream.send(new TextEncoder().encode("GET / HTTP/1.1\r\n\r\n"));
const reader = stream.readable.getReader();
// ... read response ...
```

## Proxy

The `proxy/` directory contains a WebSocket-to-TCP forwarder:

```bash
# Required: set allowlist for security
export RATLS_PROXY_ALLOWLIST="vllm.example.com:443,other.tee.com:443"
export RATLS_PROXY_LISTEN="127.0.0.1:9000"

cargo run -p ratls-proxy
```

The proxy just forwards bytes - it doesn't terminate TLS. All encryption and attestation verification happens in the browser.

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
