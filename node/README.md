# atls-node

Attested TLS connections for Node.js. Connect securely to Trusted Execution Environments (TEEs) with cryptographic proof of their integrity.

## Installation

```bash
npm install atls-node
```

Prebuilt binaries are included for:
- macOS (x64, arm64)
- Linux (x64, arm64) with glibc or musl
- Windows (x64)

## Quick Start

```typescript
import { createAtlsFetch } from "atls-node"

const fetch = createAtlsFetch("enclave.example.com")
const response = await fetch("/api/secure-data")

console.log(response.attestation.trusted)  // true
console.log(response.attestation.teeType)  // "tdx"
```

## Usage with AI SDK

Connect to LLM inference servers running in TEEs (vLLM, etc.):

```typescript
import { createAtlsFetch } from "atls-node"
import { createOpenAI } from "@ai-sdk/openai"
import { streamText } from "ai"

const fetch = createAtlsFetch({
  target: "enclave.example.com",
  onAttestation: (att) => console.log(`TEE verified: ${att.teeType}`)
})

const openai = createOpenAI({
  baseURL: "https://enclave.example.com/v1",
  apiKey: process.env.OPENAI_API_KEY,
  fetch
})

// Use .chat() for OpenAI-compatible servers (vLLM, etc.)
const { textStream } = await streamText({
  model: openai.chat("your-model"),
  messages: [{ role: "user", content: "Hello from a verified TEE!" }]
})

for await (const chunk of textStream) {
  process.stdout.write(chunk)
}
```

> **Note**: Use `openai.chat(model)` instead of `openai(model)` for OpenAI-compatible servers. AI SDK v5's default uses the Responses API which most servers don't support yet.

## API

### `createAtlsFetch(target)`

Create an attested fetch function with a simple target string:

```typescript
const fetch = createAtlsFetch("enclave.example.com")
// or with port
const fetch = createAtlsFetch("enclave.example.com:8443")
```

### `createAtlsFetch(options)`

Create with full configuration:

```typescript
const fetch = createAtlsFetch({
  target: "enclave.example.com",      // Required: host with optional port
  serverName: "enclave.example.com",  // Optional: SNI override
  headers: { "X-Custom": "value" },   // Optional: default headers
  onAttestation: (attestation) => {   // Optional: attestation callback
    if (!attestation.trusted) {
      throw new Error("Attestation failed!")
    }
    console.log("TEE:", attestation.teeType)
    console.log("TCB:", attestation.tcbStatus)
  }
})
```

### `createAtlsAgent(options)`

For use with `https.request`, axios, or other HTTP clients:

```typescript
import { createAtlsAgent } from "atls-node"
import https from "https"

const agent = createAtlsAgent({
  target: "enclave.example.com",
  onAttestation: (att) => console.log("Verified:", att.teeType)
})

// Use with https.request
https.get("https://enclave.example.com/api", { agent }, (res) => {
  // res.socket.atlsAttestation contains attestation data
})

// Use with axios
import axios from "axios"
const client = axios.create({ httpsAgent: agent })
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
cargo build -p atls-node --release

# Run the demo
node examples/ai-sdk-openai-demo.mjs "Hello from aTLS"
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
- Publish platform-specific packages (`@atls-node/darwin-arm64`, etc.)
- Publish the main `atls-node` package

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
| `@atls-node/darwin-arm64` | macOS Apple Silicon |
| `@atls-node/darwin-x64` | macOS Intel |
| `@atls-node/linux-x64-gnu` | Linux x64 (glibc) |
| `@atls-node/linux-x64-musl` | Linux x64 (musl/Alpine) |
| `@atls-node/linux-arm64-gnu` | Linux ARM64 (glibc) |
| `@atls-node/linux-arm64-musl` | Linux ARM64 (musl/Alpine) |
| `@atls-node/win32-x64-msvc` | Windows x64 |

## How It Works

1. **Direct TCP Connection** - Connects directly to the TEE endpoint (no proxy needed)
2. **TLS Handshake** - Establishes TLS with the server
3. **Quote Extraction** - Retrieves attestation quote from the server certificate
4. **DCAP Verification** - Verifies the quote against Intel's attestation infrastructure
5. **Request Execution** - Proceeds with the HTTP request over the verified channel

All verification happens automatically on each request. The attestation result is exposed on every response for audit logging or policy enforcement.

## TypeScript Support

Full TypeScript definitions are included:

```typescript
import { createAtlsFetch, AtlsFetch, AtlsAttestation, AtlsResponse } from "atls-node"

const fetch: AtlsFetch = createAtlsFetch("enclave.example.com")

const response: AtlsResponse = await fetch("/api")
const attestation: AtlsAttestation = response.attestation
```
