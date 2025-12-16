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
        │──── stream.write(request) ───►│──── encrypted ───────►│──── raw ────────►│
        │◄─── stream.read() ────────────│◄──── encrypted ───────│◄──── raw ────────│
```

## Building

```bash
# From repo root
make build-wasm

# Or directly
cd wasm && wasm-pack build --target web --out-dir pkg
```

**macOS note:** Requires Clang with WebAssembly target support:
```bash
brew install llvm
CC=/opt/homebrew/opt/llvm/bin/clang ./build-wasm.sh
```

## API

### Low-level: `AttestedStream`

Direct access to the attested TLS stream:

```typescript
import init, { AttestedStream } from "ratls-wasm";

await init();

// Connect via proxy and perform RA-TLS handshake
const stream = await AttestedStream.connect(
  "ws://127.0.0.1:9000?target=vllm.example.com:443",
  "vllm.example.com"
);

// Check attestation
const att = stream.attestation();
console.log(att.trusted, att.teeType, att.tcbStatus);

// Read/write raw bytes
await stream.write(new TextEncoder().encode("GET / HTTP/1.1\r\n\r\n"));
const response = await stream.read(8192);

// Close when done
await stream.close();
```

### High-level: `createRatlsFetch()`

Fetch-compatible API with HTTP handling in JavaScript:

```typescript
import init from "ratls-wasm";
import { createRatlsFetch } from "ratls-wasm/ratls-fetch.js";

await init();

const ratlsFetch = createRatlsFetch({
  proxyUrl: "ws://127.0.0.1:9000",
  targetHost: "vllm.example.com:443",
  onAttestation: (att) => {
    console.log(`TEE verified: ${att.teeType}, trusted: ${att.trusted}`);
  }
});

// Use like regular fetch
const response = await ratlsFetch("/v1/chat/completions", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ model: "gpt", messages: [...] })
});

// Standard Response API
console.log(response.status);
const data = await response.json();

// Attestation attached to response
console.log(response.attestation);
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

A browser demo is included in `demo/`:

```bash
# Terminal 1: Start proxy
RATLS_PROXY_ALLOWLIST="vllm.concrete-security.com:443" cargo run -p ratls-proxy

# Terminal 2: Serve demo
cd wasm && python3 -m http.server 8080

# Browser: http://localhost:8080/demo/
```
