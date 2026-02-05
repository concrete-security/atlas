# atlas-node

attested TLS (aTLS) connections for Node.js. Connect securely to Trusted Execution Environments (TEEs).

> **For aTLS protocol details, policy configuration, and security features, see [core/README.md](../core/README.md)**

## Installation

```bash
npm install @concrete-security/atlas-node
```

Prebuilt binaries are included for:
- macOS (x64, arm64)
- Linux (x64, arm64)
- Windows (x64, arm64)

## Quick Start

```typescript
import { createAtlsFetch } from "@concrete-security/atlas-node"

const fetch = createAtlsFetch("enclave.example.com")
const response = await fetch("/api/secure-data")

console.log(response.attestation.trusted)  // true
console.log(response.attestation.teeType)  // "tdx"
```

## Usage with AI SDK

Connect to LLM inference servers running in TEEs (vLLM, etc.):

```typescript
import { createAtlsFetch } from "@concrete-security/atlas-node"
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
import { createAtlsAgent } from "@concrete-security/atlas-node"
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

### `closeAllSockets()`

Close all open aTLS connections. Use for graceful shutdown in long-running processes:

```typescript
import { closeAllSockets } from "@concrete-security/atlas-node/binding"

// Before process exit
await closeAllSockets()
process.exit(0)
```

**Recommended for:**
- Server processes with graceful shutdown handlers
- Test suites that need clean teardown
- CLI tools that need clean exit

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

Common TCB status values: `UpToDate`, `SWHardeningNeeded`, `ConfigurationNeeded`, `OutOfDate`.

For complete TCB status descriptions and production recommendations, see [core/README.md#tcb-status-values](../core/README.md#tcb-status-values).

## Policy Configuration

Policies control attestation verification requirements. Pass a policy object to `createAtlsFetch` or `createAtlsAgent`:

```typescript
const fetch = createAtlsFetch({
  target: "enclave.example.com",
  policy: {
    type: "dstack_tdx",
    allowed_tcb_status: ["UpToDate", "SWHardeningNeeded"],
    expected_bootchain: {
      mrtd: "b24d3b24...",
      rtmr0: "24c15e08...",
      rtmr1: "6e1afb74...",
      rtmr2: "89e73ced..."
    },
    os_image_hash: "86b18137...",
    app_compose: {
      runner: "docker-compose",
      docker_compose_file: "..."
    }
  }
})
```

For complete policy field descriptions, verification flow, and computing bootchain measurements, see:
- [core/README.md#policy-configuration](../core/README.md#policy-configuration)
- [core/BOOTCHAIN-VERIFICATION.md](../core/BOOTCHAIN-VERIFICATION.md)

## Building from Source

Requires Rust 1.88+ and Node.js 18+:

```bash
# Build the native module
cargo build -p atlas-node --release

# Run the demo
node examples/ai-sdk-openai-demo.mjs "Hello from aTLS"
```

### Version Management

All package versions (main package, platform packages, and optionalDependencies) must stay in sync. Use the version sync script:

```bash
cd node
pnpm sync-versions 0.2.0
```

This updates:
- Main `package.json` version
- All `optionalDependencies` versions in main package
- All platform package versions in `npm/*/package.json`

### Platform Packages

The main package has optional dependencies on platform-specific packages:

| Package | Platform |
|---------|----------|
| `@concrete-security/atlas-node-darwin-arm64` | macOS Apple Silicon |
| `@concrete-security/atlas-node-darwin-x64` | macOS Intel |
| `@concrete-security/atlas-node-linux-x64-gnu` | Linux x64 |
| `@concrete-security/atlas-node-linux-arm64-gnu` | Linux ARM64 |
| `@concrete-security/atlas-node-win32-x64-msvc` | Windows x64 |
| `@concrete-security/atlas-node-win32-arm64-msvc` | Windows ARM64 |

## How It Works

Node.js bindings connect directly to TEE endpoints via TCP (no proxy required):

1. **TLS Handshake** - Establishes TLS 1.3 with session binding via EKM
2. **Quote Retrieval** - Fetches attestation quote from the server
3. **Verification** - Validates quote against policy using Intel DCAP
4. **Request Execution** - Proceeds with HTTP request over verified channel

All verification happens automatically. The attestation result is exposed on every response for audit logging or policy enforcement.

For detailed protocol specification and security features, see [core/README.md#protocol-specification](../core/README.md#protocol-specification).

## TypeScript Support

Full TypeScript definitions are included:

```typescript
import { createAtlsFetch, AtlsFetch, AtlsAttestation, AtlsResponse } from "@concrete-security/atlas-node"

const fetch: AtlsFetch = createAtlsFetch("enclave.example.com")

const response: AtlsResponse = await fetch("/api")
const attestation: AtlsAttestation = response.attestation
```
