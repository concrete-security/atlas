# ratls-node

Attested TLS connections for Node.js. Connect directly to Trusted Execution Environments (TEEs) with cryptographic proof of their integrity.

## Installation

```bash
npm install ratls-node
```

The package automatically installs the correct prebuilt binary for your platform:
- macOS (x64, arm64)
- Linux (x64, arm64) with glibc or musl
- Windows (x64)

## Quick Start

```typescript
import { createRatlsFetch } from "ratls-node"

// One-liner: creates a fetch function with RA-TLS verification
const fetch = createRatlsFetch("enclave.example.com")

const response = await fetch("/api/secure-data")
console.log(response.attestation.trusted) // true
```

## Usage with AI SDKs

Works seamlessly with OpenAI-compatible APIs running in TEEs:

```typescript
import { createRatlsFetch } from "ratls-node"
import { createOpenAI } from "@ai-sdk/openai"
import { streamText } from "ai"

const openai = createOpenAI({
  baseURL: "https://enclave.example.com/v1",
  apiKey: process.env.OPENAI_API_KEY,
  fetch: createRatlsFetch({
    target: "enclave.example.com",
    headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
    onAttestation: (att) => console.log(`Verified ${att.teeType} enclave`)
  })
})

const { textStream } = await streamText({
  model: openai("gpt-4"),
  messages: [{ role: "user", content: "Hello from a verified TEE!" }]
})

for await (const chunk of textStream) {
  process.stdout.write(chunk)
}
```

## API

### `createRatlsFetch(target)`

Create an attested fetch function with a simple target string:

```typescript
const fetch = createRatlsFetch("enclave.example.com")
// or with port
const fetch = createRatlsFetch("enclave.example.com:8443")
```

### `createRatlsFetch(options)`

Create with full configuration:

```typescript
const fetch = createRatlsFetch({
  // Target host (required)
  target: "enclave.example.com",

  // SNI override (optional, defaults to target hostname)
  serverName: "enclave.example.com",

  // Default headers for all requests
  headers: {
    Authorization: "Bearer token",
    "X-Custom-Header": "value"
  },

  // Callback for attestation events
  onAttestation: (attestation) => {
    console.log("TEE type:", attestation.teeType)
    console.log("Trusted:", attestation.trusted)
    console.log("TCB status:", attestation.tcbStatus)

    // Enforce security policy
    if (attestation.tcbStatus !== "UpToDate") {
      console.warn("Platform needs security updates")
    }
  }
})
```

### Response Type

The fetch function returns a standard `Response` with an additional `attestation` property:

```typescript
const response = await fetch("/api/data")

// Standard Response properties
console.log(response.status)        // 200
console.log(response.headers)       // Headers object
const data = await response.json()  // Parse body

// Attestation data
console.log(response.attestation)
// {
//   trusted: true,
//   teeType: "tdx",
//   measurement: "abc123...",
//   tcbStatus: "UpToDate",
//   advisoryIds: []
// }
```

## Attestation Object

| Property | Type | Description |
|----------|------|-------------|
| `trusted` | `boolean` | Whether attestation verification succeeded |
| `teeType` | `string` | TEE type (`"tdx"`, `"sgx"`) |
| `measurement` | `string \| null` | Workload measurement (MRTD/MRENCLAVE) |
| `tcbStatus` | `string` | Platform security status |
| `advisoryIds` | `string[]` | Applicable security advisories |

### TCB Status Values

- `UpToDate` - Platform is fully patched
- `SWHardeningNeeded` - Software mitigations required
- `ConfigurationNeeded` - Configuration changes needed
- `OutOfDate` - Platform needs updates

## Building from Source

Requires Rust 1.88+ and Node.js 18+:

```bash
# Build the native module
cargo build -p ratls-node --release

# Run the demo
node examples/ai-sdk-openai-demo.mjs "Hello from RA-TLS"
```

### Using napi-rs CLI

For development with hot-reload or to build platform-specific binaries:

```bash
cd node
pnpm install
pnpm build          # Build for current platform (release)
pnpm build:debug    # Build for current platform (debug)
```

## Publishing to npm

The package uses [@napi-rs/cli](https://napi.rs) for cross-platform native module distribution.

### Automated Publishing (CI)

1. Add `NPM_TOKEN` secret to your GitHub repository settings
2. Create and push a version tag:

```bash
git tag v0.1.0
git push --tags
```

The GitHub Actions workflow will:
- Build native binaries for all platforms (macOS, Linux, Windows)
- Publish platform-specific packages (`@ratls-node/darwin-arm64`, etc.)
- Publish the main `ratls-node` package

### Manual Publishing

```bash
# Dry run from GitHub Actions UI
# Go to Actions → "Publish Node Package" → Run workflow → Enable "Dry run"

# Or publish locally (single platform only)
cd node
pnpm build
npm publish
```

### Platform Packages

The main package has optional dependencies on platform-specific packages:

| Package | Platform |
|---------|----------|
| `@ratls-node/darwin-arm64` | macOS Apple Silicon |
| `@ratls-node/darwin-x64` | macOS Intel |
| `@ratls-node/linux-x64-gnu` | Linux x64 (glibc) |
| `@ratls-node/linux-x64-musl` | Linux x64 (musl/Alpine) |
| `@ratls-node/linux-arm64-gnu` | Linux ARM64 (glibc) |
| `@ratls-node/linux-arm64-musl` | Linux ARM64 (musl/Alpine) |
| `@ratls-node/win32-x64-msvc` | Windows x64 |

## HTTP Stack & Streaming

- Uses Hyper (HTTP/1.1) over the RA-TLS transport, so request/response framing and chunked encoding are handled by a well-tested library instead of custom parsing.
- Low-level streaming (`stream_read`) respects an optional `maxBytes` hint (default 8192) when splitting incoming chunks, useful for bounded reads or SSE-style consumption.

## How It Works

1. **Direct TCP Connection** - Connects directly to the TEE endpoint (no proxy needed)
2. **TLS Handshake** - Establishes TLS with the server
3. **Quote Extraction** - Retrieves attestation quote from the server certificate
4. **DCAP Verification** - Verifies the quote against Intel's attestation infrastructure
5. **Request Execution** - Proceeds with the HTTP request over the verified channel

All verification happens automatically on each request. The attestation result is exposed on every response for audit logging or policy enforcement.

## Comparison: Before & After

### Before (verbose)

```typescript
import { createRatlsFetch } from "./node/ratls-fetch.js"

const ratlsFetch = await createRatlsFetch({
  targetHost: "vllm.example.com:443",
  serverName: "vllm.example.com",  // redundant
  defaultHeaders: { Authorization: "..." }
})

// Check attestation manually
const res = await ratlsFetch("/api")
console.log(res.ratlsAttestation)  // hidden property
```

### After (elegant)

```typescript
import { createRatlsFetch } from "ratls-node"

const fetch = createRatlsFetch({
  target: "vllm.example.com",  // SNI inferred
  headers: { Authorization: "..." },
  onAttestation: (att) => console.log(att)  // declarative
})

const res = await fetch("/api")
console.log(res.attestation)  // enumerable property
```

## TypeScript Support

Full TypeScript definitions are included:

```typescript
import { createRatlsFetch, RatlsFetch, RatlsAttestation, RatlsResponse } from "ratls-node"

const fetch: RatlsFetch = createRatlsFetch("enclave.example.com")

const response: RatlsResponse = await fetch("/api")
const attestation: RatlsAttestation = response.attestation
```
