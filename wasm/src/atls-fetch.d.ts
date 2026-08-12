export interface AttestationResult {
  trusted: boolean;
  teeType: string;
  tcbStatus: string;
}

export interface AtlsFetchOptions {
  proxyUrl: string;
  targetHost: string;
  policy: Record<string, unknown>;
  serverName?: string;
  defaultHeaders?: Record<string, string>;
  onAttestation?: (attestation: AttestationResult) => void;
}

export interface AtlsResponse extends Response {
  readonly attestation: AttestationResult;
}

export interface AtlsFetch {
  (input: RequestInfo | URL, init?: RequestInit): Promise<AtlsResponse>;
  /** Close this fetch instance's pooled connection. The next request reconnects. */
  close(): void;
}

export function createAtlsFetch(options: AtlsFetchOptions): AtlsFetch;

export { AttestedStream } from "./atls_wasm.js";
