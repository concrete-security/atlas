
// private-ai-sdk: wraps any AI SDK provider so all HTTP traffic goes through aTLS (attested TLS).
//
// Why: when an AI model runs inside a TEE (Trusted Execution Environment), you want
// cryptographic proof that the server is genuine before sending data. aTLS does that.
//
// How it works:
//   1. The host app passes a SDK factory function (e.g., createAnthropic)
//   2. We create an aTLS-secured `fetch` that verifies the server's attestation
//   3. We call the SDK factory with our secure fetch instead of the default one
//   4. The host gets back a normal AI SDK provider — it doesn't know about aTLS
//
// Why a factory function and not a package name string?
//   In a compiled binary, node_modules don't exist on disk. require("@ai-sdk/anthropic")
//   would fail. The host resolves the SDK from its bundled providers and passes the
//   factory function directly — no filesystem lookup needed.

import { readFileSync } from "fs"
import { resolve, isAbsolute } from "path"
import {
  createAtlsFetch,
  type AtlsAttestation,        // The "proof received" object (what the server actually proves)
  type Policy,                 // The "expected rules" object (what the server MUST prove)
} from "@concrete-security/atlas-node"

/** SDK factory signature — any create* function from @ai-sdk/* packages. */
type SdkFactory = (config: Record<string, unknown>) => unknown

export interface AtlasProviderOptions {
  /** Provider name (passed by the host application as providerID). */
  name?: string
  /** Base URL of the AI API (e.g., "https://vllm.example.com/v1"). */
  baseURL?: string
  /** API key for the endpoint. */
  apiKey?: string
  /**
   * SDK factory function (REQUIRED).
   * The host app passes this from its bundled providers (e.g., createAnthropic).
   */
  sdk: SdkFactory
  /** aTLS target host:port. If omitted, derived from baseURL. */
  target?: string
  /** Path to the JSON policy file for aTLS verification (REQUIRED). Relative paths resolve from cwd. */
  policyFile: string
  /** Called after each aTLS attestation (useful for logging or status indicators). */
  onAttestation?: (attestation: AtlsAttestation) => void
  /** Extra options forwarded as-is to the underlying SDK. */
  [key: string]: unknown
}

/** Last attestation result, exposed for status indicators (e.g., UI badges). */
let _lastAttestation: AtlsAttestation | null = null

export function getAttestation(): AtlsAttestation | null {
  return _lastAttestation
}

/**
 * Create an AI SDK provider whose traffic is secured by aTLS.
 */
export function createAtlasProvider(options: AtlasProviderOptions) {
  const {
    sdk,
    target: targetOverride,
    policyFile,
    onAttestation: userOnAttestation,
    fetch: _unusedFetch, // Destructured to exclude from sdkOptions — we replace it with aTLS fetch
    ...sdkOptions
  } = options

  // --- Validate sdk ---
  if (typeof sdk !== "function") {
    throw new Error(
      `private-ai-sdk: "sdk" must be a factory function, got ${typeof sdk}. ` +
        "The host must pass the bundled SDK factory (e.g., createAnthropic), not a string."
    )
  }

  // --- Load policy from file ---
  const resolved = isAbsolute(policyFile) ? policyFile : resolve(process.cwd(), policyFile)
  let policy: Policy
  try {
    policy = JSON.parse(readFileSync(resolved, "utf-8"))
  } catch (err) {
    throw new Error(
      `private-ai-sdk: failed to read policy file "${policyFile}": ${(err as Error).message}`
    )
  }

  // --- Resolve aTLS target (host:port) ---
  let finalTarget: string
  if (targetOverride) {
    finalTarget = targetOverride
  } else if (sdkOptions.baseURL && typeof sdkOptions.baseURL === "string") {
    const url = new URL(sdkOptions.baseURL)
    const defaultPort = url.protocol === "http:" ? "80" : "443"
    finalTarget = `${url.hostname}:${url.port || defaultPort}`
  } else {
    throw new Error(
      'private-ai-sdk: "target" or "baseURL" is required for aTLS connection.'
    )
  }

  // --- Build aTLS fetch: verifies attestation, then sends HTTP over the attested channel ---
  const atlsFetch = createAtlsFetch({
    target: finalTarget,
    policy,
    onAttestation: (attestation) => {
      _lastAttestation = attestation
      if (!attestation.trusted) {
        throw new Error(
          "aTLS attestation failed: server is not trusted. " +
          `TEE type: ${attestation.teeType}, TCB status: ${attestation.tcbStatus}`
        )
      }
      userOnAttestation?.(attestation)
    },
  })

  // --- Create the provider with our secure fetch swapped in ---
  return sdk({
    ...sdkOptions,
    fetch: atlsFetch,
  })
}
