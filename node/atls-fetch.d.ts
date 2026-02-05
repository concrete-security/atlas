import { Agent, AgentOptions } from "https"
import { Duplex } from "stream"

// ============================================================================
// Policy Types
// ============================================================================

/**
 * Expected bootchain measurements for TDX verification
 */
export interface ExpectedBootchain {
  /** MRTD measurement (hex-encoded) */
  mrtd: string
  /** RTMR0 measurement (hex-encoded) */
  rtmr0: string
  /** RTMR1 measurement (hex-encoded) */
  rtmr1: string
  /** RTMR2 measurement (hex-encoded) */
  rtmr2: string
}

/**
 * App compose configuration for dstack deployments.
 * Use mergeWithDefaultAppCompose() to fill in defaults.
 */
export interface AppCompose {
  /** Docker compose file content */
  docker_compose_file: string
  /** Environment variables allowed to be passed to the container */
  allowed_envs?: string[]
  /** Additional fields from default app compose */
  [key: string]: unknown
}

/**
 * Policy for dstack TDX verification.
 *
 * For production, provide expected_bootchain, os_image_hash, and app_compose.
 * For development only, set disable_runtime_verification: true.
 */
export interface DstackTdxPolicy {
  type: "dstack_tdx"
  /** Expected bootchain measurements (MRTD, RTMR0-2) */
  expected_bootchain?: ExpectedBootchain
  /** Expected OS image hash (SHA256, hex-encoded) */
  os_image_hash?: string
  /** Expected app compose configuration */
  app_compose?: AppCompose
  /** Allowed TCB status values (default: ["UpToDate"]) */
  allowed_tcb_status?: string[]
  /** PCCS URL for collateral fetching */
  pccs_url?: string
  /** Cache collateral to avoid repeated fetches */
  cache_collateral?: boolean
  /**
   * Disable runtime verification (NOT RECOMMENDED for production).
   *
   * When false (default), all runtime fields (expected_bootchain, app_compose,
   * os_image_hash) must be provided or verification will fail.
   * Set to true only for development/testing.
   */
  disable_runtime_verification?: boolean
}

/**
 * Verification policy. Currently supports dstack TDX, extensible for other TEE types.
 */
export type Policy = DstackTdxPolicy

/**
 * Merge user-provided app_compose with default values.
 *
 * This allows users to provide only the fields they care about
 * (typically docker_compose_file and allowed_envs) and get a complete
 * app_compose configuration with all required default fields filled in.
 *
 * @example
 * ```ts
 * const appCompose = mergeWithDefaultAppCompose({
 *   docker_compose_file: "services:\n  app:\n    image: myapp",
 *   allowed_envs: ["API_KEY", "SECRET_TOKEN"]
 * })
 * ```
 */
export function mergeWithDefaultAppCompose(userCompose: Partial<AppCompose>): AppCompose

// ============================================================================
// Attestation Types
// ============================================================================

/**
 * Attestation result from aTLS handshake
 */
export interface AtlsAttestation {
  /** Whether the attestation verification succeeded */
  trusted: boolean
  /** Type of Trusted Execution Environment (e.g., "tdx", "sgx") */
  teeType: string
  /** Workload measurement hash (hex-encoded) */
  measurement: string | null
  /** TCB (Trusted Computing Base) status */
  tcbStatus: string
  /** Security advisory IDs that apply to this platform */
  advisoryIds: string[]
}

/**
 * Response type with attestation data
 */
export type AtlsResponse = Response & { attestation?: AtlsAttestation }

/**
 * Fetch function type returned by createAtlsFetch
 */
export type AtlsFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<AtlsResponse>

/**
 * Options for createAtlsFetch
 */
export interface AtlsFetchOptions {
  /** Target host with optional port (e.g., "enclave.example.com" or "enclave.example.com:8443") */
  target: string
  /** Verification policy */
  policy: Policy
  /** Optional SNI hostname override */
  serverName?: string
  /** Default headers applied to every request */
  headers?: Record<string, string>
  /**
   * Callback invoked after attestation, before request proceeds.
   * Throw an error to reject the connection.
   */
  onAttestation?: (attestation: AtlsAttestation) => void
}

/**
 * Create a fetch function that uses aTLS for requests to the configured target (other hosts use native fetch)
 *
 * @example Production usage with full verification
 * ```ts
 * import { createAtlsFetch, mergeWithDefaultAppCompose } from "atlas-node"
 *
 * const policy: Policy = {
 *   type: "dstack_tdx",
 *   expected_bootchain: {
 *     mrtd: "b24d3b24...",
 *     rtmr0: "24c15e08...",
 *     rtmr1: "6e1afb74...",
 *     rtmr2: "89e73ced..."
 *   },
 *   os_image_hash: "86b18137...",
 *   app_compose: mergeWithDefaultAppCompose({
 *     docker_compose_file: "services:\n  app:\n    image: myapp",
 *     allowed_envs: ["API_KEY"]
 *   }),
 *   allowed_tcb_status: ["UpToDate", "SWHardeningNeeded"]
 * }
 *
 * const fetch = createAtlsFetch({ target: "enclave.example.com", policy })
 * const response = await fetch("/api/data")
 * console.log(response.attestation?.teeType) // "tdx"
 * ```
 *
 * @example Development only (NOT for production)
 * ```ts
 * // WARNING: disable_runtime_verification skips bootchain/app_compose/os_image checks
 * // Use ONLY for development/testing, NEVER in production
 * const devPolicy: Policy = {
 *   type: "dstack_tdx",
 *   disable_runtime_verification: true,  // DEV ONLY
 *   allowed_tcb_status: ["UpToDate", "SWHardeningNeeded", "OutOfDate"]
 * }
 *
 * const fetch = createAtlsFetch({ target: "enclave.example.com", policy: devPolicy })
 * ```
 *
 * @example With AI SDK
 * ```ts
 * import { createAtlsFetch } from "atlas-node"
 * import { createOpenAI } from "@ai-sdk/openai"
 *
 * const fetch = createAtlsFetch({
 *   target: "enclave.example.com",
 *   policy,
 *   onAttestation: (att) => console.log("TEE:", att.teeType)
 * })
 * const openai = createOpenAI({ baseURL: "https://enclave.example.com/v1", fetch })
 * ```
 */
export function createAtlsFetch(options: AtlsFetchOptions): AtlsFetch

// --- Advanced: https.Agent for use with axios, https.request, etc. ---

/**
 * A Duplex socket with aTLS attestation attached
 */
export interface AtlsSocket extends Duplex {
  readonly atlsAttestation: AtlsAttestation
  readonly encrypted: true
  readonly authorized: boolean
  readonly authorizationError: string | null
}

/**
 * Options for createAtlsAgent
 */
export interface AtlsAgentOptions extends AgentOptions {
  /** Target host with optional port */
  target: string
  /** Verification policy */
  policy: Policy
  /** Optional SNI hostname override */
  serverName?: string
  /** Callback invoked after attestation */
  onAttestation?: (attestation: AtlsAttestation, socket: AtlsSocket) => void
}

/**
 * Create an https.Agent for use with axios, https.request, etc.
 * For most use cases, prefer createAtlsFetch() instead.
 */
export function createAtlsAgent(options: AtlsAgentOptions): Agent

export default createAtlsFetch
