
// AI SDK provider wrapper with aTLS (attested TLS) for Trusted Execution Environments.
//
// 1- Requires an aTLS policy (via `policy` or `policyFile` option)
// 2- Creates a special fetch via createAtlsFetch() that:
//    - opens an attested TLS connection to host:port
//    - verifies the attestation against the policy
//    - then sends HTTP requests over this channel
// 3- Dynamically loads an AI SDK (e.g., @ai-sdk/openai-compatible) from the host application
// 4- Returns the SDK provider, but with fetch replaced by the aTLS fetch.
//
// Works with any host application (the host application, custom agents, scripts, etc.)
// as long as the SDK is available in the host's node_modules.

import { createRequire } from "module"
import { readFileSync } from "fs"
import { join, resolve, isAbsolute } from "path"
import {
  createAtlsFetch,             // Builds a secure "fetch" (HTTP client) using aTLS
  type AtlsAttestation,        // The "proof received" object (what the server actually proves)
  type Policy,                 // The "expected rules" object (what the server MUST prove)
} from "@concrete-security/atlas-node"

// require() that resolves from the host application, not from this package.
// createRequire() expects a file path, so we point to the host's package.json.
// This lets us load SDKs installed in the host (e.g., @ai-sdk/openai-compatible)
// without declaring them as our own dependencies.
const hostRequire = createRequire(join(process.cwd(), "package.json"))

export interface AtlasProviderOptions {
  /** Provider name (passed by the host application as providerID) */
  name?: string
  /** Base URL of the AI API (e.g., "https://vllm.concrete-security.com/v1") */
  baseURL?: string
  /** API key for the endpoint */
  apiKey?: string
  /**
   * npm package name of the underlying AI SDK (REQUIRED).
   * Provided by the host application via config options.
   * Example: "@ai-sdk/openai-compatible", "@ai-sdk/anthropic"
   *
   * The SDK is loaded at runtime via require() from the host application's bundled
   * modules. This package declares no dependency on any SDK — the host application
   * controls the version entirely.
   */
  sdk: string
  /**
   * aTLS target host:port override.
   * If not provided, derived from baseURL (e.g., "vllm.concrete-security.com:443").
   */
  target?: string
  /**
   * aTLS verification policy override.
   * If not provided, falls back to `policyFile`. One of the two is required.
   */
  policy?: Policy
  /**
   * Path to a JSON file containing the aTLS verification policy.
   * If both `policy` and `policyFile` are provided, `policy` takes precedence.
   * Relative paths are resolved from process.cwd().
   */
  policyFile?: string
  /** Callback invoked after each successful aTLS attestation. */
  onAttestation?: (attestation: AtlsAttestation) => void
  /** Any other options are forwarded to the underlying SDK. */
  [key: string]: unknown
}

/** Stores the latest attestation for external access (e.g., status indicators). */
let _lastAttestation: AtlsAttestation | null = null

/**
 * Get the latest aTLS attestation result.
 * Returns null if no connection has been established yet.
 */
export function getAttestation(): AtlsAttestation | null {
  return _lastAttestation
}

/**
 * Create an AI SDK provider that communicates over aTLS.
 *
 * 1. Takes the SDK name from options.sdk (required, provided by the host application config)
 * 2. Loads it at runtime via require() — resolves from the host application's bundled modules
 * 3. Creates an aTLS-secured fetch via @concrete-security/atlas-node
 * 4. Returns the SDK provider with fetch replaced by aTLS fetch
 *
 * The result is transparent to the host application — it just sees a standard AI SDK provider.
 */
export function createAtlasProvider(options: AtlasProviderOptions) {
  const {
    sdk,
    target: targetOverride,
    policy: policyOverride,
    policyFile,
    onAttestation: userOnAttestation,
    fetch: _ignoredFetch,
    ...sdkOptions
  } = options

  // --- Validate required fields ---
  if (!sdk) {
    throw new Error(
      'atlas-ai-provider: "sdk" is required. ' +
        'Set it in config options (e.g., "sdk": "@ai-sdk/openai-compatible")'
    )
  }

  // --- Resolve policy (required: either policy object or policyFile path) ---
  let policy: Policy
  if (policyOverride) {
    policy = policyOverride
  } else if (policyFile) {
    const resolved = isAbsolute(policyFile) ? policyFile : resolve(process.cwd(), policyFile)
    try {
      policy = JSON.parse(readFileSync(resolved, "utf-8"))
    } catch (err) {
      throw new Error(
        `atlas-ai-provider: failed to read policy file "${policyFile}": ${(err as Error).message}`
      )
    }
  } else {
    throw new Error(
      'atlas-ai-provider: "policy" or "policyFile" is required. ' +
        "Provide a Policy object or a path to a JSON policy file."
    )
  }

  // --- Derive aTLS target from baseURL if not explicitly provided ---
  let finalTarget: string
  if (targetOverride) {
    finalTarget = targetOverride
  } else if (sdkOptions.baseURL && typeof sdkOptions.baseURL === "string") {
    const url = new URL(sdkOptions.baseURL)
    const defaultPort = url.protocol === "http:" ? "80" : "443"
    finalTarget = `${url.hostname}:${url.port || defaultPort}`
  } else {
    throw new Error(
      'atlas-ai-provider: "target" or "baseURL" is required for aTLS connection'
    )
  }

  // --- Create aTLS-secured fetch ---
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

  // --- Load the underlying SDK (provided by the host application) ---
  let createSdk: Function
  try {
    const sdkMod = hostRequire(sdk)
    const createFnKey = Object.keys(sdkMod).find((k) => k.startsWith("create"))
    if (!createFnKey) {
      throw new Error(`No create* function found in module "${sdk}"`)
    }
    createSdk = sdkMod[createFnKey]
  } catch (err) {
    throw new Error(
      `atlas-ai-provider: failed to load SDK "${sdk}". ` +
        `Make sure it is installed in the host application. Error: ${(err as Error).message}`
    )
  }

  // --- Return the wrapped provider ---
  return createSdk({
    ...sdkOptions,
    fetch: atlsFetch,
  })
}
