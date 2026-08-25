export interface AttestationResult {
  trusted: boolean;
  teeType: string;
  tcbStatus: string;
  advisoryIds: string[];
}

export interface DstackTdxPolicy {
  type: "dstack_tdx";
  expected_bootchain?: {
    mrtd: string;
    rtmr0: string;
    rtmr1: string;
    rtmr2: string;
  };
  os_image_hash?: string;
  app_compose?: Record<string, unknown>;
  allowed_tcb_status?: string[];
  /**
   * Max age (seconds) of attestation evidence before transparent
   * re-attestation of the connection. Default: 300. Set to 0 to disable
   * re-attestation completely; non-zero values below 30 are rejected.
   */
  reattestation_interval_secs?: number;
  pccs_url?: string;
  cache_collateral?: boolean;
  disable_runtime_verification?: boolean;
}

export type Policy = DstackTdxPolicy;

export interface AtlsFetchOptions {
  proxyUrl: string;
  targetHost: string;
  /** Verification policy (required). */
  policy: Policy;
  serverName?: string;
  defaultHeaders?: Record<string, string>;
  /** Called on new connections and on every re-attestation. */
  onAttestation?: (attestation: AttestationResult) => void | Promise<void>;
}

export interface AtlsResponse extends Response {
  readonly attestation: AttestationResult;
}

export type AtlsFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<AtlsResponse>;

export function createAtlsFetch(options: AtlsFetchOptions): AtlsFetch;

export { AttestedStream } from "./atls_wasm.js";
