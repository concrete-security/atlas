/**
 * aTLS Demo with AI SDK
 *
 * Demonstrates streaming chat completions through an attested TLS connection
 * to a vLLM instance running in a Trusted Execution Environment.
 *
 * Usage:
 *   node examples/ai-sdk-openai-demo.mjs "Your prompt here"
 *
 * Environment:
 *   ATLS_TARGET    - Target host (default: vllm.concrete-security.com:443)
 *   OPENAI_API_KEY  - API key for authentication
 *   OPENAI_MODEL    - Model ID (default: openai/gpt-oss-120b)
 */

import { createAtlsFetch } from "../atls-fetch.js"
import { createOpenAI } from "@ai-sdk/openai"
import { streamText } from "ai"

// Configuration
const target = process.env.ATLS_TARGET || "vllm.concrete-security.com"
const apiKey = process.env.OPENAI_API_KEY || "dummy-key"
const model = process.env.OPENAI_MODEL || "openai/gpt-oss-120b"
const prompt = process.argv.slice(2).join(" ").trim() || "Say hello from Node aTLS!"

// Track attestation for final summary
let lastAttestation = null

// Create attested fetch - one-liner with attestation callback
const fetch = createAtlsFetch({
  target,
  onAttestation: (attestation) => {
    lastAttestation = attestation
    console.log(`\n✓ TEE verified: ${attestation.teeType.toUpperCase()}`)
    console.log(`  TCB status: ${attestation.tcbStatus}`)
    if (attestation.advisoryIds.length > 0) {
      console.log(`  Advisories: ${attestation.advisoryIds.join(", ")}`)
    }
    console.log()
  }
})

// Create OpenAI client with attested fetch
const openai = createOpenAI({
  apiKey,
  baseURL: `https://${target}/v1`,
  fetch,
})

console.log(`Connecting to ${target}...`)
console.log(`Model: ${model}`)
console.log(`Prompt: "${prompt}"`)

// Stream the response using Chat Completions API (vLLM doesn't support Responses API)
const { textStream } = await streamText({
  model: openai.chat(model),
  messages: [{ role: "user", content: prompt }],
})

process.stdout.write("\nResponse: ")
for await (const text of textStream) {
  process.stdout.write(text)
}

// Summary
console.log("\n")
console.log("─".repeat(50))
if (lastAttestation) {
  console.log("Attestation Summary:")
  console.log(`  Trusted: ${lastAttestation.trusted ? "✓ Yes" : "✗ No"}`)
  console.log(`  TEE Type: ${lastAttestation.teeType}`)
  console.log(`  TCB Status: ${lastAttestation.tcbStatus}`)
  if (lastAttestation.measurement) {
    console.log(`  Measurement: ${lastAttestation.measurement.slice(0, 16)}...`)
  }
} else {
  console.log("⚠ No attestation received")
}
