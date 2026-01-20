/**
 * aTLS Fetch - Attested fetch for Trusted Execution Environments
 *
 * @example Production usage with full verification
 * ```js
 * import { createAtlsFetch, mergeWithDefaultAppCompose } from "atls-node"
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
 * const fetch = createAtlsFetch({ target: "enclave.example.com", policy })
 * const response = await fetch("/api/data")
 * console.log(response.attestation.teeType) // "tdx"
 * ```
 *
 * @example Development only (NOT for production)
 * ```js
 * import { createAtlsFetch } from "atls-node"
 *
 * // WARNING: disable_runtime_verification skips bootchain/app_compose/os_image checks
 * // Use ONLY for development/testing, NEVER in production
 * const devPolicy = {
 *   type: "dstack_tdx",
 *   disable_runtime_verification: true,  // DEV ONLY
 *   allowed_tcb_status: ["UpToDate", "SWHardeningNeeded", "OutOfDate"]
 * }
 *
 * const fetch = createAtlsFetch({ target: "enclave.example.com", policy: devPolicy })
 * ```
 *
 * @example With AI SDK
 * ```js
 * import { createAtlsFetch } from "atls-node"
 * import { createOpenAI } from "@ai-sdk/openai"
 *
 * const fetch = createAtlsFetch({
 *   target: "enclave.example.com",
 *   policy: productionPolicy,
 *   onAttestation: (att) => console.log("TEE:", att.teeType)
 * })
 * const openai = createOpenAI({ baseURL: "https://enclave.example.com/v1", fetch })
 * ```
 */

import { Agent, request as httpsRequest } from "https"
import { Duplex, Readable } from "stream"
import { createRequire } from "module"

const DEBUG = !!process.env.ATLS_DEBUG
const debug = (...args) => {
  if (DEBUG) {
    console.error("[atls]", ...args)
  }
}

const require = createRequire(import.meta.url)
const {
  atlsConnect,
  socketRead,
  socketWrite,
  socketClose,
  socketDestroy,
  mergeWithDefaultAppCompose,
} = require("./index.cjs")

/**
 * Parse target host string into host:port format
 * @param {string} target - Host with optional port
 * @returns {{ host: string, port: string, hostPort: string, serverName: string }}
 */
function parseTarget(target) {
  const trimmed = target.trim()
  const withoutProtocol = trimmed.replace(/^https?:\/\//, "")
  const hostPart = withoutProtocol.split("/")[0]

  const [host, port = "443"] = hostPart.split(":")
  return {
    host,
    port,
    hostPort: `${host}:${port}`,
    serverName: host,
  }
}

/**
 * Create a Duplex stream backed by a Rust aTLS socket
 * @param {number} socketId - Socket handle from Rust
 * @param {object} attestation - Attestation result
 * @returns {Duplex & { atlsAttestation: object }}
 */
function createAtlsDuplex(socketId, attestation, meta) {
  let reading = false
  let destroyed = false

  debug("socket:create", { socketId, host: meta?.host, port: meta?.port })

  function scheduleRead(size) {
    if (reading || destroyed) return
    reading = true

    debug("socket:read:start", { socketId, size: size || 16384 })

    socketRead(socketId, size || 16384)
      .then((buf) => {
        reading = false
        if (destroyed) return
        if (!buf || buf.length === 0) {
          debug("socket:read:eof", { socketId })
          duplex.push(null)
          return
        }
        debug("socket:read", { socketId, bytes: buf.length })
        const shouldContinue = duplex.push(buf)
        if (shouldContinue) {
          scheduleRead(size)
        }
      })
      .catch((err) => {
        reading = false
        if (!destroyed) {
          debug("socket:read:error", { socketId, err: err?.message })
          duplex.destroy(err)
        }
      })
  }

  const duplex = new Duplex({
    read(size) {
      scheduleRead(size)
    },

    write(chunk, encoding, callback) {
      if (destroyed) {
        callback(new Error("Socket destroyed"))
        return
      }

      debug("socket:write", { socketId, bytes: chunk?.length })
      socketWrite(socketId, Buffer.from(chunk))
        .then(() => callback())
        .catch(callback)
    },

    final(callback) {
      // Do not close here; HTTP keep-alive and response reading depend on the socket staying open.
      callback()
    },

    destroy(err, callback) {
      if (!destroyed) {
        destroyed = true
        debug("socket:destroy", { socketId, err: err?.message })
        socketDestroy(socketId)
      }
      callback(err)
    },
  })

  // No-op socket tuning hooks expected by http/https internals
  duplex.setKeepAlive = (_enable = false, _initialDelay = 0) => duplex
  duplex.setNoDelay = (_noDelay = true) => duplex
  duplex.setTimeout = (_ms, cb) => {
    if (cb) duplex.once("timeout", cb)
    return duplex
  }
  duplex.ref = () => duplex
  duplex.unref = () => duplex

  duplex.remoteAddress = meta?.host
  duplex.remotePort = meta?.port ? parseInt(meta.port, 10) : undefined
  duplex.alpnProtocol = "http/1.1"
  duplex.connecting = false

  process.nextTick(() => {
    debug("socket:ready", { socketId })
    duplex.emit("connect")
    duplex.emit("secureConnect")
  })

  // Attach attestation as property
  duplex.atlsAttestation = attestation

  // Mark as TLS-connected socket (required for https.Agent)
  duplex.encrypted = true
  duplex.authorized = attestation.trusted
  duplex.authorizationError = attestation.trusted ? null : "ATTESTATION_FAILED"

  // Emit attestation event
  process.nextTick(() => duplex.emit("attestation", attestation))

  return duplex
}

/**
 * Create an https.Agent that establishes aTLS connections
 *
 * @param {AtlsAgentOptions} options - Options object with target and policy
 * @returns {Agent} An https.Agent that uses aTLS sockets
 *
 * @example
 * // Production usage with full verification
 * const agent = createAtlsAgent({
 *   target: "enclave.example.com:8443",
 *   policy: {
 *     type: "dstack_tdx",
 *     expected_bootchain: { mrtd: "...", rtmr0: "...", rtmr1: "...", rtmr2: "..." },
 *     os_image_hash: "...",
 *     app_compose: { docker_compose_file: "...", allowed_envs: [] },
 *     allowed_tcb_status: ["UpToDate", "SWHardeningNeeded"]
 *   },
 *   onAttestation: (attestation, socket) => {
 *     console.log("Verified TEE:", attestation.teeType)
 *   }
 * })
 */
export function createAtlsAgent(options) {
  if (typeof options === "string") {
    throw new Error(
      "String shorthand no longer supported - policy is required. Use: { target, policy }"
    )
  }

  const targetRaw = options.target
  if (!targetRaw) {
    throw new Error(
      "target is required (e.g., 'enclave.example.com' or 'enclave.example.com:443')"
    )
  }

  const policy = options.policy
  if (!policy) {
    throw new Error(
      "policy is required for aTLS verification. See docs for policy format."
    )
  }

  const parsed = parseTarget(targetRaw)
  const effectiveServerName = options.serverName || parsed.serverName
  const onAttestation = options.onAttestation

  // Extract agent-specific options
  const { target, serverName, onAttestation: _, policy: __, ...agentOptions } = options

  class AtlsAgent extends Agent {
    createConnection(connectOptions, callback) {
      atlsConnect(parsed.hostPort, effectiveServerName, policy)
        .then(({ socketId, attestation }) => {
          const socket = createAtlsDuplex(socketId, attestation, parsed)

          // Call user's attestation callback before returning socket
          if (onAttestation) {
            try {
              onAttestation(attestation, socket)
            } catch (err) {
              socket.destroy(err)
              return callback(err)
            }
          }

          callback(null, socket)
        })
        .catch(callback)
    }
  }

  return new AtlsAgent({
    keepAlive: true,
    ...agentOptions,
  })
}

/**
 * Create a fetch function that uses aTLS for requests to the target,
 * and falls back to native global fetch for everything else.
 *
 * @param {AtlsFetchOptions} options - Options object with target and policy
 * @returns {Function} A fetch-compatible function
 *
 * @example
 * const fetch = createAtlsFetch({
 *   target: "enclave.example.com",
 *   policy: {
 *     type: "dstack_tdx",
 *     expected_bootchain: { mrtd: "...", rtmr0: "...", rtmr1: "...", rtmr2: "..." },
 *     os_image_hash: "...",
 *     app_compose: { docker_compose_file: "...", allowed_envs: [] },
 *     allowed_tcb_status: ["UpToDate", "SWHardeningNeeded"]
 *   }
 * })
 * const res = await fetch("/api/data", { method: "POST", body: JSON.stringify({}) })
 *
 * @example With AI SDK
 * const fetch = createAtlsFetch({ target: "enclave.example.com", policy, onAttestation: console.log })
 * const openai = createOpenAI({ baseURL: "https://enclave.example.com/v1", fetch })
 */
export function createAtlsFetch(options) {
  if (typeof options === "string") {
    throw new Error(
      "String shorthand no longer supported - policy is required. Use: { target, policy }"
    )
  }

  if (!options.target) {
    throw new Error(
      "target is required (e.g., 'enclave.example.com' or 'enclave.example.com:443')"
    )
  }

  if (!options.policy) {
    throw new Error(
      "policy is required for aTLS verification. See docs for policy format."
    )
  }

  const parsed = parseTarget(options.target)
  const agent = createAtlsAgent(options)
  const defaultHeaders = options.headers || undefined

  return async function atlsFetch(input, init = {}) {
    let destUrl = null
    let isRelative = false

    try {
      if (input instanceof URL) {
        destUrl = input
      } else if (typeof input === "string") {
        destUrl = new URL(input)
      } else if (input && typeof input === "object" && input.url) {
        destUrl = new URL(input.url)
      }
    } catch (e) {
      isRelative = true
    }

    const shouldProxy = isRelative || (destUrl?.hostname === parsed.host)

    if (!shouldProxy) {
      const urlString = destUrl?.toString() ?? (typeof input === "string" ? input : input?.url ?? String(input))
      debug("fetch:passthrough", { url: urlString })
      return globalThis.fetch(input, init)
    }

    const url = new URL(input, `https://${parsed.hostPort}`)
    const headers = mergeHeaders(defaultHeaders, init.headers)
    const { body, contentLength, kind } = normalizeBody(init.body)

    debug("fetch:request", {
      url: url.toString(),
      method: init.method || "GET",
      headers,
      bodyKind: kind,
      contentLength,
    })

    return new Promise((resolve, reject) => {
      const reqOptions = {
        hostname: parsed.host,
        port: parseInt(parsed.port),
        path: url.pathname + url.search,
        method: init.method || "GET",
        headers,
        agent,
      }

      if (contentLength != null && headers["content-length"] == null) {
        reqOptions.headers = { ...headers, "content-length": contentLength }
      }

      const req = httpsRequest(reqOptions, (res) => {
        debug("fetch:response", {
          status: res.statusCode,
          headers: res.headers,
        })
        const attestation = res.socket?.atlsAttestation
        const responseHeaders = toWebHeaders(res.headers)
        const webStream = Readable.toWeb(res)

        const response = new Response(webStream, {
          status: res.statusCode || 0,
          statusText: res.statusMessage || "",
          headers: responseHeaders,
        })

        if (attestation) {
          Object.defineProperty(response, "attestation", {
            value: attestation,
            enumerable: true,
          })
        }

        resolve(response)
      })

      req.on("error", reject)

      if (init.signal) {
        if (init.signal.aborted) {
          req.destroy(init.signal.reason)
          return reject(init.signal.reason)
        }
        init.signal.addEventListener("abort", () => {
          req.destroy(init.signal.reason)
        })
      }

      if (!body) {
        req.end()
        return
      }

      switch (kind) {
        case "buffer":
          req.end(body)
          return
        case "readable-stream": {
          const reader = body.getReader()
          const pump = () => reader.read()
            .then(({ done, value }) => {
              if (done) {
                req.end()
                return
              }
              req.write(Buffer.from(value))
              pump()
            })
            .catch((err) => req.destroy(err))
          pump()
          return
        }
        case "async-iterable":
          ;(async () => {
            try {
              for await (const chunk of body) {
                req.write(Buffer.from(chunk))
              }
              req.end()
            } catch (err) {
              req.destroy(err)
            }
          })()
          return
        default:
          req.end()
      }
    })
  }
}

function mergeHeaders(defaultHeaders, overrideHeaders) {
  const headers = new Headers()
  if (defaultHeaders) {
    new Headers(defaultHeaders).forEach((value, name) => headers.set(name, value))
  }
  if (overrideHeaders) {
    new Headers(overrideHeaders).forEach((value, name) => headers.set(name, value))
  }
  const result = {}
  headers.forEach((value, name) => {
    result[name] = value
  })
  return result
}

function toWebHeaders(nodeHeaders) {
  const headers = new Headers()
  for (const [name, value] of Object.entries(nodeHeaders || {})) {
    if (Array.isArray(value)) {
      value.forEach((v) => headers.append(name, v))
    } else if (value !== undefined) {
      headers.set(name, String(value))
    }
  }
  return headers
}

function normalizeBody(body) {
  if (!body) return { body: null, contentLength: null, kind: "none" }

  if (typeof body === "string") {
    const buf = Buffer.from(body)
    return { body: buf, contentLength: buf.length, kind: "buffer" }
  }

  if (Buffer.isBuffer(body) || body instanceof Uint8Array) {
    return { body: Buffer.from(body), contentLength: body.length, kind: "buffer" }
  }

  if (body instanceof ArrayBuffer) {
    const buf = Buffer.from(body)
    return { body: buf, contentLength: buf.length, kind: "buffer" }
  }

  if (body instanceof ReadableStream) {
    return { body, contentLength: null, kind: "readable-stream" }
  }

  if (typeof body[Symbol.asyncIterator] === "function") {
    return { body, contentLength: null, kind: "async-iterable" }
  }

  // Fallback: stringify unknown objects
  const buf = Buffer.from(String(body))
  return { body: buf, contentLength: buf.length, kind: "buffer" }
}

// Re-export merge utility for users to construct app_compose
export { mergeWithDefaultAppCompose }

export default createAtlsAgent
