/**
 * RA-TLS Fetch - A fetch-compatible API for attested TLS connections.
 *
 * This module provides a fetch-like API that delegates HTTP handling to the
 * WASM module (including chunked transfer encoding for streaming LLM responses).
 *
 * @example Production usage with full verification
 * ```js
 * import { init, createRatlsFetch, mergeWithDefaultAppCompose } from "ratls-fetch.js"
 *
 * await init()
 *
 * const policy = {
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
 * const fetch = createRatlsFetch({
 *   proxyUrl: "ws://localhost:9000",
 *   targetHost: "enclave.example.com",
 *   policy
 * })
 * const response = await fetch("/api/data")
 * ```
 *
 * @example Development only (NOT for production)
 * ```js
 * // WARNING: disable_runtime_verification skips bootchain/app_compose/os_image checks
 * // Use ONLY for development/testing, NEVER in production
 * const devPolicy = {
 *   type: "dstack_tdx",
 *   disable_runtime_verification: true,  // DEV ONLY
 *   allowed_tcb_status: ["UpToDate", "SWHardeningNeeded", "OutOfDate"]
 * }
 * ```
 */

import init, { AttestedStream, RatlsHttp, mergeWithDefaultAppCompose } from "./ratls_wasm.js";

// ============================================================================
// WASM Initialization
// ============================================================================

let wasmReady;

async function ensureWasm() {
  if (!wasmReady) {
    wasmReady = init();
  }
  return wasmReady;
}

// ============================================================================
// Connection Pool (for HTTP keep-alive / connection reuse)
// ============================================================================

/**
 * Connection cache keyed by (wsUrl, serverName).
 * Each entry holds an RatlsHttp instance that can be reused.
 * @type {Map<string, RatlsHttp>}
 */
const connectionCache = new Map();

/**
 * Close all cached connections.
 * Call this when you want to clean up resources.
 */
export function closeAllConnections() {
  for (const http of connectionCache.values()) {
    try {
      http.close();
    } catch (e) {
      // Ignore errors during cleanup
    }
  }
  connectionCache.clear();
}

/**
 * Get the number of cached connections.
 * @returns {{ total: number }}
 */
export function getConnectionPoolStats() {
  return { total: connectionCache.size };
}

// ============================================================================
// URL Helpers
// ============================================================================

function isLoopbackHostname(host) {
  const value = host?.toLowerCase?.() || "";
  return value === "localhost" || value === "127.0.0.1" || value === "::1" || value.startsWith("127.");
}

function normalizeProxyUrl(raw) {
  if (!raw) return "";
  const candidate = /^wss?:\/\//i.test(raw) ? raw : `ws://${raw.replace(/^\/+/, "")}`;
  try {
    const url = new URL(candidate);
    const isProd = typeof process !== "undefined" && process?.env?.NODE_ENV === "production";
    if (isProd && url.protocol !== "wss:" && !isLoopbackHostname(url.hostname)) {
      throw new Error("RA-TLS proxy URL must use wss:// in production");
    }
    return url.toString();
  } catch (error) {
    if (error instanceof Error && /must use wss/i.test(error.message || "")) {
      throw error;
    }
    return candidate;
  }
}

function normalizeTarget(value) {
  if (!value) return "";
  return value.includes(":") ? value : `${value}:443`;
}

function buildProxyUrl(base, target) {
  const url = new URL(normalizeProxyUrl(base));
  if (target) {
    url.searchParams.set("target", target);
  }
  return url.toString();
}

// ============================================================================
// Main API
// ============================================================================

/**
 * Create a fetch-compatible function for attested TLS connections.
 *
 * Connections are automatically pooled and reused for subsequent requests
 * to the same target. The `onAttestation` callback is called only once
 * when a new connection is established (not on reused connections).
 *
 * @param {Object} options
 * @param {string} options.proxyUrl - WebSocket proxy URL (e.g., "ws://127.0.0.1:9000")
 * @param {string} options.targetHost - Target TEE server (e.g., "vllm.example.com:443")
 * @param {Object} options.policy - Verification policy
 * @param {string} [options.serverName] - TLS server name (defaults to hostname from targetHost)
 * @param {Object} [options.defaultHeaders] - Default headers to include in all requests
 * @param {Function} [options.onAttestation] - Callback when attestation is received (only on new connections)
 * @returns {Function} A fetch-compatible async function
 */
export function createRatlsFetch(options) {
  const { proxyUrl, targetHost, serverName, defaultHeaders, onAttestation, policy } = options;

  if (!proxyUrl || !targetHost) {
    throw new Error("proxyUrl and targetHost are required for RA-TLS fetch");
  }

  if (!policy) {
    throw new Error("policy is required for RATLS verification. See docs for policy format.");
  }

  const normalizedTarget = normalizeTarget(targetHost);
  const sni = serverName || normalizedTarget.split(":")[0];
  const host = normalizedTarget.split(":")[1] === "443"
    ? normalizedTarget.split(":")[0]
    : normalizedTarget;
  const wsUrl = buildProxyUrl(proxyUrl, normalizedTarget);
  const base = new URL(`https://${normalizedTarget}`);

  // Cache key for this connection target
  const cacheKey = `${wsUrl}|${sni}`;

  return async function ratlsFetch(input, init = {}) {
    await ensureWasm();

    // Try to reuse an existing connection
    let http = connectionCache.get(cacheKey);
    let attestation;

    if (http && http.isReady()) {
      // Reuse existing connection - no re-attestation needed
      attestation = http.attestation();
    } else {
      // Need to create a new connection
      // First, clean up any stale connection
      if (http) {
        try {
          http.close();
        } catch (e) {
          // Ignore cleanup errors
        }
        connectionCache.delete(cacheKey);
      }

      // Connect and perform RA-TLS handshake with policy
      http = await RatlsHttp.connect(wsUrl, sni, policy);
      connectionCache.set(cacheKey, http);

      // Get attestation
      attestation = http.attestation();

      // Call attestation callback ONLY for new connections
      if (onAttestation && typeof onAttestation === "function") {
        try {
          await onAttestation(attestation);
        } catch (e) {
          console.error("[ratls-fetch] onAttestation callback failed:", e);
          // Clean up the connection on attestation callback failure
          connectionCache.delete(cacheKey);
          try { http.close(); } catch (_) {}
          throw e;
        }
      }
    }

    // Build request from input
    const request = new Request(input, init);
    const url = new URL(request.url, base);
    const path = `${url.pathname}${url.search}`;

    // Merge headers (default + request headers)
    const mergedHeaders = [];
    if (defaultHeaders) {
      for (const [name, value] of Object.entries(defaultHeaders)) {
        mergedHeaders.push([name, value]);
      }
    }
    request.headers.forEach((value, name) => {
      // Override default headers with request headers
      const idx = mergedHeaders.findIndex(([n]) => n.toLowerCase() === name.toLowerCase());
      if (idx >= 0) {
        mergedHeaders[idx] = [name, value];
      } else {
        mergedHeaders.push([name, value]);
      }
    });

    // Get body as Uint8Array
    let body = null;
    if (request.body) {
      body = new Uint8Array(await request.arrayBuffer());
    }

    // Perform HTTP request via WASM (handles chunked encoding)
    let result;
    try {
      result = await http.fetch(
        request.method,
        path,
        host,
        mergedHeaders,
        body
      );
    } catch (e) {
      // On request failure, remove the connection from cache
      connectionCache.delete(cacheKey);
      try { http.close(); } catch (_) {}
      throw e;
    }

    // Convert headers object to Headers instance
    const responseHeaders = new Headers();
    for (const [name, value] of Object.entries(result.headers)) {
      responseHeaders.append(name, value);
    }

    // Create Response object with body stream from WASM
    const response = new Response(result.body, {
      status: result.status,
      statusText: result.statusText,
      headers: responseHeaders
    });

    // Attach attestation as non-enumerable property
    Object.defineProperty(response, "attestation", {
      value: attestation,
      enumerable: false,
      configurable: false,
      writable: false
    });

    return response;
  };
}

// Re-export for advanced usage
export { init, AttestedStream, RatlsHttp, mergeWithDefaultAppCompose };
