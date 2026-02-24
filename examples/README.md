# Examples

This directory contains example applications built on top of Atlas (ratls).

## private-ai-sdk

An [AI SDK](https://sdk.vercel.ai/) provider wrapper that secures model inference with aTLS. It wraps any AI SDK provider (OpenAI, Anthropic, etc.) and replaces the HTTP transport with an attested TLS channel, ensuring the model runs inside a verified TEE.

Used by [secure-opencode](https://github.com/concrete-security/secure-opencode) to provide secure inference in the terminal.

See [`private-ai-sdk/`](./private-ai-sdk/) for setup and usage.
