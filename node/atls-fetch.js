/**
 * aTLS Fetch - Attested fetch for Trusted Execution Environments
 *
 * @example Production usage with full verification
 * ```js
 * import { createAtlsFetch, mergeWithDefaultAppCompose } from "atlas-node"
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
 * import { createAtlsFetch } from "atlas-node"
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
 * import { createAtlsFetch } from "atlas-node"
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
  socketReattestIfDue,
  mergeWithDefaultAppCompose,
} = require("./index.cjs")

/**
 * Parse target host string into host:port format
 * @param {string} target - Host with optional port
 * @returns {{ host: string, port: string, hostPort: string, serverName: string }}
 */
function parseTarget(target) {
  // Example input:
  // "enclave.example.com:8443"
  const trimmed = target.trim()
  const withoutProtocol = trimmed.replace(/^https?:\/\//, "")
  const hostPart = withoutProtocol.split("/")[0]

  const [host, port = "443"] = hostPart.split(":")
  return {
    host,                          //  "enclave.example.com"
    port,                          //  "8443"
    hostPort: `${host}:${port}`,   //  "enclave.example.com:8443"
    serverName: host,
  }
}

/**
 * Resolve input to a destination URL and decide whether to proxy via aTLS.
 * @returns {{ shouldProxy: boolean, url: URL | null }}
 */
function resolveDestination(input, parsed) {
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
  }

  const urlStr = destUrl?.toString() ?? (typeof input === "string" ? input : input?.url ?? String(input))
  return { shouldProxy, url: shouldProxy ? new URL(urlStr, `https://${parsed.hostPort}`) : destUrl }
}

/**
 * Attach attestation as a property on a Response object.
 */
function attachAttestation(response, attestation) {
  if (attestation) {
    Object.defineProperty(response, "attestation", {
      value: attestation,
      enumerable: true,
    })
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

// Node's setTimeout treats delays above 2^31-1 ms as 1 ms; skip the timer for
// such far-out expiries (keepSocketAlive still checks the wall clock).
const MAX_TIMEOUT_MS = 0x7fffffff

/**
 * Stamp attestation-evidence expiry bookkeeping on an agent socket and arm an
 * unref'd timer that retires it if it expires while idle in the pool.
 *
 * The https.Agent path cannot re-attest in-band: Node's HTTP machinery keeps
 * a read pending on pooled sockets, which would swallow the quote response.
 * Expired sockets are retired instead — the next request transparently opens
 * a fresh connection, which performs a full fresh attestation.
 */
function armEvidenceExpiry(socket, intervalSecs) {
  socket.atlsVerifiedAt = Date.now()
  socket.atlsExpiresAt =
    intervalSecs > 0 ? socket.atlsVerifiedAt + intervalSecs * 1000 : Infinity
  socket.atlsIdle = false
  if (socket.atlsExpiresAt === Infinity) return

  // Chain timers for expiries beyond Node's setTimeout clamp (2^31 - 1 ms):
  // a single oversized setTimeout would fire after ~1 ms instead of waiting.
  let timer = null
  const arm = () => {
    const remaining = socket.atlsExpiresAt - Date.now()
    if (remaining > MAX_TIMEOUT_MS) {
      timer = setTimeout(arm, MAX_TIMEOUT_MS)
    } else {
      timer = setTimeout(() => {
        if (socket.atlsIdle) {
          debug("agent:destroy-idle-expired", { expiresAt: socket.atlsExpiresAt })
          socket.destroy()
        } else {
          // Busy with an in-flight response; keepSocketAlive() retires it when
          // the response completes.
          socket.atlsExpired = true
        }
      }, Math.max(remaining, 0))
    }
    timer.unref?.()
  }
  arm()
  socket.once("close", () => clearTimeout(timer))
}

/** Error code used when a request is denied because the pooled socket's attestation evidence expired. */
const ATLS_EVIDENCE_EXPIRED = "ATLS_EVIDENCE_EXPIRED"

/** Whether an agent socket's attestation evidence has expired. */
function atlsEvidenceExpired(socket) {
  return socket.atlsExpired === true || Date.now() >= (socket.atlsExpiresAt ?? Infinity)
}

/**
 * Create an https.Agent that establishes aTLS connections
 *
 * Attestation evidence expires after the policy's
 * `reattestation_interval_secs` (default 300; 0 disables): expired sockets
 * are never reused and the next request reconnects with a fresh, fully
 * attested connection. `onAttestation` fires again for each new connection.
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
        .then(({ socketId, attestation, reattestationIntervalSecs }) => {
          const socket = createAtlsDuplex(socketId, attestation, parsed)
          armEvidenceExpiry(socket, reattestationIntervalSecs)

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

    keepSocketAlive(socket) {
      socket.atlsIdle = true
      if (atlsEvidenceExpired(socket)) {
        // Retire instead of pooling: the next request reconnects, which
        // performs a full fresh attestation (fail closed by construction).
        debug("agent:retire-expired", { expiresAt: socket.atlsExpiresAt })
        return false
      }
      return super.keepSocketAlive(socket)
    }

    reuseSocket(socket, req) {
      if (atlsEvidenceExpired(socket)) {
        // Fail closed: never dispatch a request on expired evidence. This
        // covers sockets that expired while idle in the pool (between the
        // unref'd timer firing and reuse, or if the process was suspended).
        // The denied request carries a tagged error; createAtlsFetch retries
        // it once on a fresh, fully attested connection.
        debug("agent:deny-expired-reuse", { expiresAt: socket.atlsExpiresAt })
        socket.atlsExpired = true
        const err = new Error(
          "aTLS attestation evidence expired; reconnect required"
        )
        err.code = ATLS_EVIDENCE_EXPIRED
        socket.destroy()
        req.destroy(err)
        return
      }
      socket.atlsIdle = false
      super.reuseSocket(socket, req)
    }
  }

  return new AtlsAgent({
    keepAlive: true,
    ...agentOptions,
  })
}

// ---------------------------------------------------------------------------
// Raw HTTP/1.1 helpers (Bun-compatible — no https.request / Agent needed)
// ---------------------------------------------------------------------------

const IDLE_TIMEOUT_MS = 300_000
const MAX_HEADER_SIZE = 64 * 1024

/**
 * Connection pool (single cached connection + overflow).
 * Avoids repeating the expensive aTLS handshake on every request.
 *
 * Reused connections are transparently re-attested in-band when their
 * attestation evidence is older than the policy's
 * `reattestation_interval_secs` (a released connection is quiescent, so the
 * quote exchange cannot interleave with request traffic). On re-attestation
 * failure the connection is destroyed and a fresh one — fully attested — is
 * opened instead (fail closed).
 *
 * `deps` is a test seam: production callers omit it.
 */
function createConnectionPool(parsed, serverName, policy, onAttestation, deps = {}) {
  const {
    atlsConnect: connectFn = atlsConnect,
    socketReattestIfDue: reattestFn = socketReattestIfDue,
    socketDestroy: destroyFn = socketDestroy,
  } = deps
  let cached = null // { socketId, busy, lastUsed, attestation }

  async function connect() {
    const { socketId, attestation } = await connectFn(
      parsed.hostPort,
      serverName,
      policy,
    )
    debug("pool:connect", { socketId })
    if (onAttestation) onAttestation(attestation)
    return { socketId, attestation, busy: true, lastUsed: Date.now() }
  }

  return {
    async acquire() {
      if (
        cached &&
        !cached.busy &&
        Date.now() - cached.lastUsed < IDLE_TIMEOUT_MS
      ) {
        debug("pool:reuse", { socketId: cached.socketId })
        cached.busy = true
        try {
          const attestation = await reattestFn(cached.socketId)
          if (attestation) {
            debug("pool:reattested", { socketId: cached.socketId })
            cached.attestation = attestation
            if (onAttestation) onAttestation(attestation)
          }
          return cached
        } catch (err) {
          // Fail closed: drop the connection and fall through to a fresh
          // connect below, which performs a full attestation.
          debug("pool:reattest-failed", {
            socketId: cached.socketId,
            err: err?.message,
          })
          try { destroyFn(cached.socketId) } catch (_) {}
          cached = null
        }
      }
      // Busy → open overflow connection (don't touch cached)
      if (cached && cached.busy) {
        debug("pool:overflow", { existingSocketId: cached.socketId })
        return await connect()
      }
      // Stale or missing — (re)connect
      if (cached) {
        debug("pool:stale", { socketId: cached.socketId })
        try { destroyFn(cached.socketId) } catch (_) {}
        cached = null
      }
      cached = await connect()
      return cached
    },

    release(socketId) {
      if (cached && cached.socketId === socketId) {
        cached.busy = false
        cached.lastUsed = Date.now()
        debug("pool:release", { socketId })
      } else {
        // overflow connection — close it
        debug("pool:release:overflow", { socketId })
        try { destroyFn(socketId) } catch (_) {}
      }
    },

    invalidate(socketId) {
      debug("pool:invalidate", { socketId })
      try { destroyFn(socketId) } catch (_) {}
      if (cached && cached.socketId === socketId) cached = null
    },
  }
}

/**
 * Format & write an HTTP/1.1 request on the raw aTLS socket.
 */
async function writeRequest(socketId, method, path, host, headers, body, contentLength, kind) {
  if (!/^[A-Z]+$/.test(method)) {
    throw new Error(`Invalid HTTP method: ${method}`)
  }

  let head = `${method} ${path} HTTP/1.1\r\nHost: ${host}\r\n`

  for (const [k, v] of Object.entries(headers)) {
    head += `${k}: ${v}\r\n`
  }

  if (contentLength != null && !headers["content-length"]) {
    head += `content-length: ${contentLength}\r\n`
  }

  if (!headers["connection"]) {
    head += "connection: keep-alive\r\n"
  }

  head += "\r\n"

  debug("raw:write-head", { socketId, headLength: head.length })

  if (!body || kind === "none") {
    await socketWrite(socketId, Buffer.from(head))
    return
  }

  if (kind === "buffer") {
    const headerBuf = Buffer.from(head)
    const combined = Buffer.concat([headerBuf, body])
    await socketWrite(socketId, combined)
    return
  }

  // Headers first, then stream body
  await socketWrite(socketId, Buffer.from(head))

  if (kind === "readable-stream") {
    const reader = body.getReader()
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      await socketWrite(socketId, Buffer.from(value))
    }
    return
  }

  if (kind === "async-iterable") {
    for await (const chunk of body) {
      await socketWrite(socketId, Buffer.from(chunk))
    }
  }
}

/**
 * Read response head (status line + headers) from the socket.
 * Returns { status, statusText, headers, extra } where extra is any
 * leftover bytes already read past the \r\n\r\n boundary.
 */
async function readResponseHead(socketId) {
  let buf = Buffer.alloc(0)

  while (true) {
    const chunk = await socketRead(socketId, 16384)
    if (!chunk || chunk.length === 0) {
      throw new Error("Connection closed before response headers received")
    }
    buf = Buffer.concat([buf, chunk])

    if (buf.length > MAX_HEADER_SIZE) {
      throw new Error("Response headers exceed 64KB limit")
    }

    const idx = buf.indexOf("\r\n\r\n")
    if (idx !== -1) {
      const headBuf = buf.subarray(0, idx)
      const extra = buf.subarray(idx + 4)
      return parseHead(headBuf, extra)
    }
  }
}

function parseHead(headBuf, extra) {
  const headStr = headBuf.toString("utf-8")
  const lines = headStr.split("\r\n")

  // Status line: "HTTP/1.1 200 OK"
  const statusLine = lines[0]
  const statusMatch = statusLine.match(/^HTTP\/\d\.\d (\d{3})(?: (.*))?$/)
  if (!statusMatch) {
    throw new Error(`Malformed status line: ${statusLine}`)
  }
  const status = parseInt(statusMatch[1], 10)
  const statusText = statusMatch[2] || ""

  // Parse headers (lowercase keys, set-cookie as array)
  const headers = {}
  for (let i = 1; i < lines.length; i++) {
    const colonIdx = lines[i].indexOf(":")
    if (colonIdx === -1) continue
    const name = lines[i].substring(0, colonIdx).trim().toLowerCase()
    const value = lines[i].substring(colonIdx + 1).trim()

    if (name === "set-cookie") {
      if (!headers[name]) headers[name] = []
      headers[name].push(value)
    } else if (headers[name] !== undefined) {
      headers[name] += `, ${value}`
    } else {
      headers[name] = value
    }
  }

  debug("raw:response-head", { status, statusText, headers })
  return { status, statusText, headers, extra }
}

/**
 * Return true if this method+status combination has no body.
 */
function hasNoBody(method, status) {
  if (method === "HEAD") return true
  if (status === 204 || status === 304) return true
  if (status >= 100 && status < 200) return true
  return false
}

/**
 * Detect stale-connection errors (server closed between requests).
 */
function isStaleConnectionError(err) {
  if (!err) return false
  const msg = (err.message || "").toLowerCase()
  return /closed|reset|epipe|broken pipe|etimedout|econnreset/.test(msg)
}

/**
 * Build a ReadableStream that yields the response body.
 * Handles chunked transfer-encoding, content-length, and EOF-delimited bodies.
 */
function readBodyStream(socketId, headers, extra, signal, pool) {
  const isChunked = (headers["transfer-encoding"] || "")
    .toLowerCase()
    .includes("chunked")
  const contentLengthStr = headers["content-length"]
  const wantClose =
    (headers["connection"] || "").toLowerCase() === "close"

  return new ReadableStream({
    start(controller) {
      // Abort signal handling
      if (signal) {
        const onAbort = () => {
          controller.error(signal.reason || new DOMException("Aborted", "AbortError"))
          pool.invalidate(socketId)
        }
        if (signal.aborted) {
          onAbort()
          return
        }
        signal.addEventListener("abort", onAbort, { once: true })
      }

      // Choose read strategy
      if (isChunked) {
        readChunked(socketId, extra, controller, pool, wantClose)
      } else if (contentLengthStr != null) {
        readContentLength(
          socketId,
          extra,
          parseInt(contentLengthStr, 10),
          controller,
          pool,
          wantClose,
        )
      } else {
        readUntilEOF(socketId, extra, controller, pool)
      }
    },

    cancel() {
      pool.invalidate(socketId)
    },
  })
}

async function readChunked(socketId, extra, controller, pool, wantClose) {
  let buf = extra && extra.length > 0 ? Buffer.from(extra) : Buffer.alloc(0)

  try {
    while (true) {
      // Find chunk-size line
      let crlfIdx = buf.indexOf("\r\n")
      while (crlfIdx === -1) {
        const chunk = await socketRead(socketId, 16384)
        if (!chunk || chunk.length === 0) {
          controller.close()
          pool.invalidate(socketId)
          return
        }
        buf = Buffer.concat([buf, chunk])
        crlfIdx = buf.indexOf("\r\n")
      }

      const sizeLine = buf.subarray(0, crlfIdx).toString("utf-8").trim()
      // Strip chunk extensions (e.g. ";ext=value")
      const sizeHex = sizeLine.split(";")[0].trim()
      const chunkSize = parseInt(sizeHex, 16)

      if (isNaN(chunkSize)) {
        controller.error(new Error(`Invalid chunk size: ${sizeLine}`))
        pool.invalidate(socketId)
        return
      }

      buf = buf.subarray(crlfIdx + 2)

      if (chunkSize === 0) {
        // Terminal chunk — consume trailers + final \r\n before reusing connection
        // Trailers end with \r\n\r\n (or just \r\n if no trailers)
        while (buf.indexOf("\r\n") === -1) {
          const trailer = await socketRead(socketId, 4096)
          if (!trailer || trailer.length === 0) break
          buf = Buffer.concat([buf, trailer])
        }
        controller.close()
        if (wantClose) {
          pool.invalidate(socketId)
        } else {
          pool.release(socketId)
        }
        return
      }

      // Read chunkSize bytes + trailing \r\n
      const needed = chunkSize + 2 // data + \r\n
      while (buf.length < needed) {
        const chunk = await socketRead(socketId, Math.max(16384, needed - buf.length))
        if (!chunk || chunk.length === 0) {
          // Premature close — enqueue what we have
          if (buf.length > 0) controller.enqueue(new Uint8Array(buf))
          controller.close()
          pool.invalidate(socketId)
          return
        }
        buf = Buffer.concat([buf, chunk])
      }

      // Enqueue chunk data immediately (critical for streaming)
      controller.enqueue(new Uint8Array(buf.subarray(0, chunkSize)))
      buf = buf.subarray(needed) // skip data + \r\n
    }
  } catch (err) {
    controller.error(err)
    pool.invalidate(socketId)
  }
}

async function readContentLength(socketId, extra, total, controller, pool, wantClose) {
  let remaining = total
  let buf = extra && extra.length > 0 ? Buffer.from(extra) : Buffer.alloc(0)

  try {
    // Enqueue any extra bytes already read
    if (buf.length > 0) {
      const toSend = buf.subarray(0, Math.min(buf.length, remaining))
      controller.enqueue(new Uint8Array(toSend))
      remaining -= toSend.length
      buf = buf.subarray(toSend.length)
    }

    while (remaining > 0) {
      const chunk = await socketRead(socketId, Math.min(16384, remaining))
      if (!chunk || chunk.length === 0) {
        controller.close()
        pool.invalidate(socketId)
        return
      }
      const toSend = chunk.subarray(0, Math.min(chunk.length, remaining))
      controller.enqueue(new Uint8Array(toSend))
      remaining -= toSend.length
    }

    controller.close()
    if (wantClose) {
      pool.invalidate(socketId)
    } else {
      pool.release(socketId)
    }
  } catch (err) {
    controller.error(err)
    pool.invalidate(socketId)
  }
}

async function readUntilEOF(socketId, extra, controller, pool) {
  try {
    if (extra && extra.length > 0) {
      controller.enqueue(new Uint8Array(extra))
    }

    while (true) {
      const chunk = await socketRead(socketId, 16384)
      if (!chunk || chunk.length === 0) {
        controller.close()
        pool.invalidate(socketId) // EOF — not reusable
        return
      }
      controller.enqueue(new Uint8Array(chunk))
    }
  } catch (err) {
    controller.error(err)
    pool.invalidate(socketId)
  }
}

// ---------------------------------------------------------------------------

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
const IS_BUN = typeof globalThis.Bun !== "undefined"

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

  if (IS_BUN) {
    return createAtlsFetchBun(options)
  }
  return createAtlsFetchNode(options)
}

/**
 * Node.js implementation — uses https.request + Agent (proven path).
 */
function createAtlsFetchNode(options) {
  const parsed = parseTarget(options.target)
  const agent = createAtlsAgent(options)
  const defaultHeaders = options.headers || undefined

  return async function atlsFetch(input, init = {}) {
    const { shouldProxy, url } = resolveDestination(input, parsed)
    if (!shouldProxy) return globalThis.fetch(input, init)

    const method = (init.method || "GET").toUpperCase()
    if (!/^[A-Z]+$/.test(method)) {
      throw new Error(`Invalid HTTP method: ${method}`)
    }
    const headers = mergeHeaders(defaultHeaders, init.headers)
    const { body, contentLength, kind } = normalizeBody(init.body)

    debug("fetch:request", {
      url: url.toString(),
      method,
      headers,
      bodyKind: kind,
      contentLength,
    })

    const attempt = (isRetry) => new Promise((resolve, reject) => {
      const reqOptions = {
        hostname: parsed.host,
        port: parseInt(parsed.port),
        path: url.pathname + url.search,
        method,
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
        const responseHeaders = toWebHeaders(res.headers)
        const webStream = Readable.toWeb(res)

        const response = new Response(webStream, {
          status: res.statusCode || 0,
          statusText: res.statusMessage || "",
          headers: responseHeaders,
        })

        attachAttestation(response, res.socket?.atlsAttestation)
        resolve(response)
      })

      req.on("error", (err) => {
        // A pooled socket was denied at dispatch because its attestation
        // evidence expired: transparently retry once — the expired socket is
        // gone, so the retry opens a fresh, fully attested connection.
        // Stream/iterable bodies cannot be replayed, so those surface the
        // error instead.
        if (
          !isRetry &&
          err?.code === ATLS_EVIDENCE_EXPIRED &&
          (!body || kind === "buffer")
        ) {
          debug("fetch:retry-expired-evidence")
          resolve(attempt(true))
          return
        }
        reject(err)
      })

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

    return attempt(false)
  }
}

/**
 * Bun implementation — raw HTTP/1.1 over aTLS socket + connection pool.
 * Bun ignores Agent.createConnection, so we bypass https.request entirely.
 */
function createAtlsFetchBun(options) {
  const parsed = parseTarget(options.target)
  const effectiveServerName = options.serverName || parsed.serverName
  const defaultHeaders = options.headers || undefined

  const pool = createConnectionPool(
    parsed,
    effectiveServerName,
    options.policy,
    options.onAttestation,
  )

  return async function atlsFetch(input, init = {}) {
    const { shouldProxy, url } = resolveDestination(input, parsed)
    if (!shouldProxy) return globalThis.fetch(input, init)

    const method = (init.method || "GET").toUpperCase()
    if (!/^[A-Z]+$/.test(method)) {
      throw new Error(`Invalid HTTP method: ${method}`)
    }
    const headers = mergeHeaders(defaultHeaders, init.headers)
    const { body, contentLength, kind } = normalizeBody(init.body)
    const path = url.pathname + url.search
    const signal = init.signal || null

    debug("fetch:request", {
      url: url.toString(),
      method,
      headers,
      bodyKind: kind,
      contentLength,
    })

    if (signal?.aborted) {
      throw signal.reason || new DOMException("Aborted", "AbortError")
    }

    for (let attempt = 0; attempt < 2; attempt++) {
      let conn
      try {
        conn = await pool.acquire()

        await writeRequest(
          conn.socketId,
          method,
          path,
          parsed.host,
          headers,
          body,
          contentLength,
          kind,
        )

        const head = await readResponseHead(conn.socketId)

        debug("fetch:response", {
          status: head.status,
          headers: head.headers,
        })

        const responseHeaders = toWebHeaders(head.headers)

        if (hasNoBody(method, head.status)) {
          pool.release(conn.socketId)
          const response = new Response(null, {
            status: head.status,
            statusText: head.statusText,
            headers: responseHeaders,
          })
          attachAttestation(response, conn.attestation)
          return response
        }

        const bodyStream = readBodyStream(
          conn.socketId,
          head.headers,
          head.extra,
          signal,
          pool,
        )

        const response = new Response(bodyStream, {
          status: head.status,
          statusText: head.statusText,
          headers: responseHeaders,
        })

        attachAttestation(response, conn.attestation)
        return response
      } catch (err) {
        if (conn) pool.invalidate(conn.socketId)

        if (attempt === 0 && isStaleConnectionError(err)) {
          debug("fetch:retry-stale", { err: err.message })
          continue
        }
        throw err
      }
    }
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

// Internal seams exposed for offline tests only — not part of the public API.
export const _internals = { createConnectionPool, armEvidenceExpiry, atlsEvidenceExpired }

export default createAtlsAgent
