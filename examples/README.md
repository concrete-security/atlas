# Examples

This directory contains example applications built on top of Atlas (ratls).

## ai-provider

An [AI SDK](https://sdk.vercel.ai/) provider wrapper that secures model inference with aTLS. It wraps any AI SDK provider (OpenAI, Anthropic, etc.) and replaces the HTTP transport with an attested TLS channel, ensuring the model runs inside a verified TEE.

Used by [secure-opencode](https://github.com/concrete-security/secure-opencode) to provide secure inference in the terminal.

See [`ai-provider/`](./ai-provider/) for setup and usage.
