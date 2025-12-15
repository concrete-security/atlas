import { Agent, AgentOptions } from "https"
import { Duplex } from "stream"

/**
 * Attestation result from RATLS handshake
 */
export interface RatlsAttestation {
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
export type RatlsResponse = Response & { attestation?: RatlsAttestation }

/**
 * Fetch function type returned by createRatlsFetch
 */
export type RatlsFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<RatlsResponse>

/**
 * Options for createRatlsFetch
 */
export interface RatlsFetchOptions {
  /** Target host with optional port (e.g., "enclave.example.com" or "enclave.example.com:8443") */
  target: string
  /** Optional SNI hostname override */
  serverName?: string
  /** Default headers applied to every request */
  headers?: Record<string, string>
  /**
   * Callback invoked after attestation, before request proceeds.
   * Throw an error to reject the connection.
   */
  onAttestation?: (attestation: RatlsAttestation) => void
}

/**
 * Create a fetch function that uses RATLS for requests to the configured target (other hosts use native fetch)
 *
 * @example Simple usage
 * ```ts
 * import { createRatlsFetch } from "ratls-node"
 *
 * const fetch = createRatlsFetch("enclave.example.com")
 * const response = await fetch("/api/data")
 * console.log(response.attestation?.teeType) // "tdx"
 * ```
 *
 * @example With AI SDK
 * ```ts
 * import { createRatlsFetch } from "ratls-node"
 * import { createOpenAI } from "@ai-sdk/openai"
 *
 * const fetch = createRatlsFetch({
 *   target: "enclave.example.com",
 *   onAttestation: (att) => console.log("TEE:", att.teeType)
 * })
 * const openai = createOpenAI({ baseURL: "https://enclave.example.com/v1", fetch })
 * ```
 */
export function createRatlsFetch(options: string | RatlsFetchOptions): RatlsFetch

// --- Advanced: https.Agent for use with axios, https.request, etc. ---

/**
 * A Duplex socket with RATLS attestation attached
 */
export interface RatlsSocket extends Duplex {
  readonly ratlsAttestation: RatlsAttestation
  readonly encrypted: true
  readonly authorized: boolean
  readonly authorizationError: string | null
}

/**
 * Options for createRatlsAgent
 */
export interface RatlsAgentOptions extends AgentOptions {
  target: string
  serverName?: string
  onAttestation?: (attestation: RatlsAttestation, socket: RatlsSocket) => void
}

/**
 * Create an https.Agent for use with axios, https.request, etc.
 * For most use cases, prefer createRatlsFetch() instead.
 */
export function createRatlsAgent(options: string | RatlsAgentOptions): Agent

export default createRatlsFetch
