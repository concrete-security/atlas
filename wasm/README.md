# wasm (browser client)

WASM bindings for aTLS attested connections. The module performs TLS 1.3 inside WASM and uses WebSocket tunnels via a proxy.

## Architecture

The WASM module handles **attested TLS + HTTP/1.1 protocol** (including chunked transfer encoding for streaming LLM responses).

```
Browser (atls-fetch.js)          WASM (atls_wasm)           Proxy              TEE
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

### `createAtlsFetch(options)`

Fetch-compatible API (HTTP handling in Rust/WASM):

```javascript
import { init, createAtlsFetch } from "./pkg/atls-fetch.js";

await init();

const fetch = createAtlsFetch({
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

### Low-level: `AtlsHttp`

HTTP client with streaming body support:

```javascript
import init, { AtlsHttp } from "./pkg/atls_wasm.js";

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
import init, { AttestedStream } from "./pkg/atls_wasm.js";

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

The `proxy/` directory contains a WebSocket-to-TCP forwarder:

```bash
# Required: set allowlist for security
export ATLS_PROXY_ALLOWLIST="vllm.example.com:443,other.tee.com:443"
export ATLS_PROXY_LISTEN="127.0.0.1:9000"

cargo run -p atls-proxy
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
