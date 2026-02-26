// Run: node test/index.test.mjs

//  cd ~/ratls/examples/private-ai-sdk
//  npm run build && node test/index.test.mjs

import { readFileSync, writeFileSync, unlinkSync } from "fs"
import { dirname, join } from "path"
import { fileURLToPath } from "url"
import { createRequire } from "module"
import { createAtlsFetch, mergeWithDefaultAppCompose } from "@concrete-security/atlas-node"

const __dirname = dirname(fileURLToPath(import.meta.url))
const require = createRequire(import.meta.url)
const { closeAllSockets } = require("@concrete-security/atlas-node/binding")

// --- Test runner ---

let passed = 0
let failed = 0

function test(name, fn) {
  return async () => {
    try {
      await fn()
      console.log(`  ✓ ${name}`)
      passed++
    } catch (err) {
      console.error(`  ✗ ${name}`)
      console.error(`    ${err.message}`)
      failed++
    }
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || "Assertion failed")
}

function assertThrows(fn, expectedSubstring) {
  try {
    fn()
    throw new Error("Expected an error but none was thrown")
  } catch (err) {
    if (err.message === "Expected an error but none was thrown") throw err
    assert(
      err.message.includes(expectedSubstring),
      `Expected "${expectedSubstring}" in error, got: "${err.message}"`
    )
  }
}

// --- Fake SDK factory for unit tests ---
const fakeSdk = (config) => ({ type: "fake-provider", config })

// --- Load module once ---
const mod = await import("../dist/index.js")
const { createAtlasProvider, getAttestation } = mod

// --- VLLM policy (used by unit test 8 and integration tests) ---

const VLLM_DOCKER_COMPOSE = readFileSync(
  join(__dirname, "../../../core/tests/data/vllm_docker_compose.yml"),
  "utf-8"
)

const VLLM_POLICY = {
  type: "dstack_tdx",
  expected_bootchain: {
    mrtd: "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
    rtmr0: "24c15e08c07aa01c531cbd7e8ba28f8cb62e78f6171bf6a8e0800714a65dd5efd3a06bf0cf5433c02bbfac839434b418",
    rtmr1: "6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7",
    rtmr2: "89e73cedf48f976ffebe8ac1129790ff59a0f52d54d969cb73455b1a79793f1dc16edc3b1fccc0fd65ea5905774bbd57",
  },
  os_image_hash: "86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a",
  app_compose: mergeWithDefaultAppCompose({
    docker_compose_file: VLLM_DOCKER_COMPOSE,
    allowed_envs: ["EKM_SHARED_SECRET", "AUTH_SERVICE_TOKEN"],
  }),
  allowed_tcb_status: ["UpToDate", "SWHardeningNeeded"],
}

const TARGET = "vllm.concrete-security.com"
const TIMEOUT = 30_000

// ============================================================================
// Unit tests
// ============================================================================

const unitTests = [
  // Test 1: the module exports the two public functions
  test("exports createAtlasProvider and getAttestation", () => {
    assert(typeof createAtlasProvider === "function")
    assert(typeof getAttestation === "function")
  }),

  // Test 2: no attestation has happened yet, should be null
  test("getAttestation returns null initially", () => {
    assert(getAttestation() === null)
  }),

  // Test 3: the host finds the factory via Object.keys(mod).find(k => k.startsWith("create"))
  test("host discovers createAtlasProvider via create* convention", () => {
    const key = Object.keys(mod).find((k) => k.startsWith("create"))
    assert(key === "createAtlasProvider", `Got: ${key}`)
  }),

  // Test 4: sdk must be a function (factory), not a string — require() is gone
  test("throws when sdk is not a function", () => {
    assertThrows(
      () => createAtlasProvider({ sdk: "a-string", policyFile: "/tmp/p.json", baseURL: "https://x.com" }),
      "must be a factory function"
    )
  }),

  // Test 5: policyFile must point to an existing file
  test("throws when policyFile does not exist", () => {
    assertThrows(
      () => createAtlasProvider({ sdk: fakeSdk, policyFile: "/nonexistent/policy.json", baseURL: "https://x.com" }),
      "failed to read policy file"
    )
  }),

  // Test 6: either baseURL or target is required to know where to connect
  test("throws without baseURL or target", () => {
    const tmp = join(__dirname, "_test_policy.json")
    writeFileSync(tmp, '{"type":"dstack_tdx"}')
    try {
      assertThrows(
        () => createAtlasProvider({ sdk: fakeSdk, policyFile: tmp }),
        '"target" or "baseURL" is required'
      )
    } finally {
      try { unlinkSync(tmp) } catch {}
    }
  }),

  // Test 7: invalid JSON in policyFile — must throw a parse error (proves parsing actually happens)
  test("throws on invalid JSON in policyFile", () => {
    const tmp = join(__dirname, "_test_policy.json")
    writeFileSync(tmp, "not valid json {{{")
    try {
      assertThrows(
        () => createAtlasProvider({ sdk: fakeSdk, policyFile: tmp, baseURL: "https://x.com" }),
        "failed to read policy file"
      )
    } finally {
      try { unlinkSync(tmp) } catch {}
    }
  }),

  // Test 8: write VLLM_POLICY to a file, load it via createAtlasProvider, validate the parsed structure
  test("policyFile is parsed with correct structure and hash lengths", () => {
    const tmp = join(__dirname, "_test_policy.json")
    writeFileSync(tmp, JSON.stringify(VLLM_POLICY))
    try {
      // Parse the file the same way createAtlasProvider does
      const policy = JSON.parse(readFileSync(tmp, "utf-8"))

      // Required top-level fields
      assert(policy.type === "dstack_tdx", `Expected type "dstack_tdx", got "${policy.type}"`)
      assert(policy.expected_bootchain, "Missing expected_bootchain")
      assert(policy.os_image_hash, "Missing os_image_hash")
      assert(policy.app_compose, "Missing app_compose")
      assert(Array.isArray(policy.allowed_tcb_status), "allowed_tcb_status should be an array")

      // Bootchain: all 4 registers must be 96-char hex strings (384-bit TDX measurements)
      const { mrtd, rtmr0, rtmr1, rtmr2 } = policy.expected_bootchain
      for (const [name, value] of [["mrtd", mrtd], ["rtmr0", rtmr0], ["rtmr1", rtmr1], ["rtmr2", rtmr2]]) {
        assert(typeof value === "string", `${name} should be a string`)
        assert(value.length === 96, `${name} should be 96 chars (got ${value.length})`)
        assert(/^[0-9a-f]+$/.test(value), `${name} should be lowercase hex`)
      }

      // os_image_hash: 64-char hex string (SHA-256)
      assert(policy.os_image_hash.length === 64, `os_image_hash should be 64 chars (got ${policy.os_image_hash.length})`)
      assert(/^[0-9a-f]+$/.test(policy.os_image_hash), "os_image_hash should be lowercase hex")

      // Also verify createAtlasProvider accepts it without error
      const provider = createAtlasProvider({ sdk: fakeSdk, policyFile: tmp, baseURL: "https://x.com" })
      assert(provider !== undefined, "Should return a provider")
    } finally {
      try { unlinkSync(tmp) } catch {}
    }
  }),
]

// ============================================================================
// Integration tests — aTLS against vllm.concrete-security.com
// ============================================================================

const integrationTests = [
  // Test 9: real aTLS handshake with a valid policy — should connect and list models
  test("correct policy → connects and returns models", async () => {
    const ac = new AbortController()
    const timer = setTimeout(() => ac.abort(), TIMEOUT)
    try {
      const fetch = createAtlsFetch({ target: TARGET, policy: VLLM_POLICY })
      const res = await fetch("/v1/models", { signal: ac.signal })

      assert(res.ok, `Expected 2xx, got ${res.status}`)
      assert(res.attestation?.trusted === true, `Attestation not trusted`)
      assert(res.attestation?.teeType === "tdx", `Expected tdx, got ${res.attestation?.teeType}`)
      assert(res.attestation?.tcbStatus?.length > 0, `Empty tcbStatus`)

      const data = await res.json()
      assert(Array.isArray(data.data) && data.data.length > 0, "No models returned")
    } finally {
      clearTimeout(timer)
    }
  }),

  // Test 10: tampered mrtd in policy — aTLS handshake must reject the server
  test("altered mrtd → rejects connection", async () => {
    const badPolicy = {
      ...VLLM_POLICY,
      expected_bootchain: {
        ...VLLM_POLICY.expected_bootchain,
        mrtd: "a" + VLLM_POLICY.expected_bootchain.mrtd.slice(1),
      },
    }
    const ac = new AbortController()
    const timer = setTimeout(() => ac.abort(), TIMEOUT)
    try {
      const fetch = createAtlsFetch({ target: TARGET, policy: badPolicy })
      await fetch("/v1/models", { signal: ac.signal })
      throw new Error("Should have rejected")
    } catch (err) {
      if (err.message === "Should have rejected") throw err
      const msg = err.message.toLowerCase()
      assert(
        msg.includes("mismatch") || msg.includes("handshake") || msg.includes("verification") || msg.includes("attestation"),
        `Expected attestation error, got: ${err.message}`
      )
    } finally {
      clearTimeout(timer)
    }
  }),
]

// ============================================================================
// Run
// ============================================================================

console.log("Unit tests\n")
for (const t of unitTests) await t()

console.log("\nIntegration tests (aTLS → vllm.concrete-security.com)\n")
for (const t of integrationTests) await t()

console.log(`\n${passed} passed, ${failed} failed`)
await closeAllSockets()
process.exit(failed > 0 ? 1 : 0)
