# Node.js Examples

Practical examples demonstrating aTLS usage in Node.js applications.

## Examples

### ai-sdk-openai-demo.mjs

Demonstrates streaming chat completions through an attested TLS connection to a vLLM instance running in a Trusted Execution Environment (TEE).

**What it demonstrates:**
- Creating an attested fetch function with `createAtlsFetch()`
- Integrating with the Vercel AI SDK
- Streaming responses from OpenAI-compatible servers (vLLM)
- Handling attestation callbacks
- Verifying TEE type and TCB status

## Prerequisites

### System Requirements

- **Node.js**: 18.0.0 or higher
- **Rust**: 1.88 or higher (for building from source)

### Dependencies

The examples require the following packages:

```bash
# Install the aTLS Node.js binding (or build from source)
npm install @concrete-security/atlas-node

# Install AI SDK dependencies (for ai-sdk-openai-demo.mjs)
npm install @ai-sdk/openai ai
```

For development (building from source):

```bash
cd node
pnpm install
```

## Running the Examples

### ai-sdk-openai-demo.mjs

#### Using the Published Package

```bash
# Install dependencies
npm install @concrete-security/atlas-node @ai-sdk/openai ai

# Run with default configuration
node examples/ai-sdk-openai-demo.mjs "Your prompt here"

# Run with custom target and model
ATLS_TARGET=your-tee.example.com:443 \
OPENAI_MODEL=meta-llama/Llama-3.1-8B-Instruct \
OPENAI_API_KEY=your-api-key \
node examples/ai-sdk-openai-demo.mjs "Explain aTLS in one sentence"
```

#### Building from Source

```bash
# From the repository root
cd node

# Install dependencies and build
pnpm install
pnpm build

# Run the example
node examples/ai-sdk-openai-demo.mjs "Hello from aTLS!"
```

## Environment Variables

### ai-sdk-openai-demo.mjs

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ATLS_TARGET` | TEE endpoint (host:port) | `vllm.concrete-security.com:443` | No |
| `OPENAI_API_KEY` | API key for authentication | `dummy-key` | No (server-dependent) |
| `OPENAI_MODEL` | Model identifier | `openai/gpt-oss-120b` | No |

**Example:**

```bash
ATLS_TARGET=10.0.0.5:8000 \
OPENAI_MODEL=meta-llama/Llama-3.1-70B-Instruct \
OPENAI_API_KEY=sk-123abc \
node examples/ai-sdk-openai-demo.mjs "What is confidential computing?"
```


For more details on the Node.js API, see [node/README.md](../README.md).

For policy configuration and protocol details, see [core/README.md](../../core/README.md).
