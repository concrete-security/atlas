# private-ai-sdk

An [AI SDK](https://sdk.vercel.ai/) provider that wraps any AI SDK (OpenAI, Anthropic, etc.) and replaces its HTTP transport with an **attested TLS (aTLS)** channel. This ensures the model you're talking to runs inside a verified **Trusted Execution Environment (TEE)**.

## Why

Standard HTTPS guarantees encryption in transit, but tells you nothing about _where_ the server runs. A compromised or rogue server can decrypt your prompts.

aTLS solves this: before any data is exchanged, the server proves it runs inside a TEE by providing an attestation report. The client verifies this report against a **policy** (expected TEE measurements). If the attestation fails, the connection is rejected.

## Who can use it

Any application built on Vercel's [AI SDK](https://sdk.vercel.ai/) — coding agents, chatbots, RAG pipelines, custom scripts — can use this provider as a drop-in replacement to get secure inference. If it uses `@ai-sdk/*`, it works with private-ai-sdk.

Currently used by:
- [**secure-opencode**](https://github.com/concrete-security/secure-opencode) — a fork of OpenCode that offers secure AI coding in the terminal.

## How it works

```
Host app (e.g. opencode)
  │
  │  config: { sdk: "@ai-sdk/anthropic", policyFile: "./cvm_policy.json" }
  │
  ▼
private-ai-sdk
  │
  │  1. Loads the policy from file or config
  │  2. Loads the AI SDK dynamically from the host's node_modules
  │  3. Creates an aTLS-secured fetch (via @concrete-security/atlas-node)
  │  4. Returns the SDK provider with fetch replaced by aTLS fetch
  │
  ▼
AI model running inside a TEE
```

The host application sees a standard AI SDK provider — the aTLS layer is transparent.

## Usage

### Install

```bash
cd examples/private-ai-sdk
pnpm install
pnpm build   # compiles to dist/
```

### Configuration

The provider is configured through the host application's config. Example with opencode (`.opencode/opencode.jsonc`):

```jsonc
{
  "provider": {
    "my-secure-provider": {
      "npm": "file:///path/to/atlas/examples/private-ai-sdk/dist/index.js",
      "api": "https://your-tee-endpoint.com/v1",
      "options": {
        "sdk": "@ai-sdk/anthropic",
        "policyFile": "/path/to/cvm_policy.json"
      },
      "models": {
        "my-model": { "id": "openai/model-name", "name": "My Secure Model" }
      }
    }
  }
}
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `sdk` | Yes | npm package name of the AI SDK (e.g. `@ai-sdk/anthropic`, `@ai-sdk/openai-compatible`) |
| `policyFile` | Yes* | Absolute path to a JSON policy file describing the expected TEE configuration |
| `policy` | Yes* | Alternative: pass the policy object directly instead of a file |
| `baseURL` | Yes | URL of the AI API running inside the TEE |
| `target` | No | Override aTLS target `host:port` (derived from `baseURL` by default) |

\* One of `policyFile` or `policy` is required.

### Tests

```bash
# Unit tests (no network)
ai-provider % cd examples/private-ai-sdk && node test/index.test.mjs
```
