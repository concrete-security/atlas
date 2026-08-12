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

export type AtlsFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<AtlsResponse>;

export function createAtlsFetch(options: AtlsFetchOptions): AtlsFetch;

export { AttestedStream } from "./atls_wasm.js";
