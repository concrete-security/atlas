/**
 * private-ai-sdk tests
 *
 * Run with: node test/index.test.mjs   (or bun test/index.test.mjs)
 *
 * Unit tests verify argument validation and SDK loading logic.
 * Integration tests connect to vllm.concrete-security.com over aTLS
 * to verify that correct policies succeed and bad policies are rejected.
 */

import { readFileSync } from "fs"
import { dirname, join } from "path"
import { fileURLToPath } from "url"
import { createRequire } from "module"
import {
  createAtlsFetch,
  mergeWithDefaultAppCompose,
} from "@concrete-security/atlas-node"

const __dirname = dirname(fileURLToPath(import.meta.url))
const require = createRequire(import.meta.url)
const { closeAllSockets } = require("@concrete-security/atlas-node/binding")

// Test helpers
let passed = 0
let failed = 0

function test(name, fn) {
  return async () => {
    try {
      await fn()
      console.log(`  \u2713 ${name}`)
      passed++
    } catch (err) {
      console.error(`  \u2717 ${name}`)
      console.error(`    Error: ${err.message}`)
      failed++
    }
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed")
  }
}

// ============================================================================
// Tests
// ============================================================================

const tests = [
  test("exports createAtlasProvider", async () => {
    const mod = await import("../dist/index.js")
    assert(typeof mod.createAtlasProvider === "function", "createAtlasProvider should be a function")
  }),

  test("exports getAttestation", async () => {
    const mod = await import("../dist/index.js")
    assert(typeof mod.getAttestation === "function", "getAttestation should be a function")
  }),

  test("getAttestation returns null initially", async () => {
    const mod = await import("../dist/index.js")
    assert(mod.getAttestation() === null, "Should return null before any connection")
  }),

  test("createAtlasProvider throws without sdk", async () => {
    const mod = await import("../dist/index.js")
    try {
      mod.createAtlasProvider({ baseURL: "https://example.com/v1", policy: { type: "dstack_tdx" } })
      throw new Error("Should have thrown")
    } catch (err) {
      assert(err.message.includes('"sdk" is required'), `Expected sdk error, got: ${err.message}`)
    }
  }),

  test("createAtlasProvider throws without policy or policyFile", async () => {
    const mod = await import("../dist/index.js")
    try {
      mod.createAtlasProvider({ sdk: "@ai-sdk/openai-compatible", baseURL: "https://example.com/v1" })
      throw new Error("Should have thrown")
    } catch (err) {
      assert(
        err.message.includes('"policy" or "policyFile" is required'),
        `Expected policy error, got: ${err.message}`
      )
    }
  }),

  test("createAtlasProvider throws without baseURL or target", async () => {
    const mod = await import("../dist/index.js")
    try {
      mod.createAtlasProvider({ sdk: "@ai-sdk/openai-compatible", policy: { type: "dstack_tdx" } })
      throw new Error("Should have thrown")
    } catch (err) {
      assert(
        err.message.includes('"target" or "baseURL" is required'),
        `Expected target/baseURL error, got: ${err.message}`
      )
    }
  }),

  test("createAtlasProvider throws for unknown SDK", async () => {
    const mod = await import("../dist/index.js")
    try {
      mod.createAtlasProvider({
        sdk: "@nonexistent/sdk-that-does-not-exist",
        baseURL: "https://example.com/v1",
        policy: { type: "dstack_tdx" },
      })
      throw new Error("Should have thrown")
    } catch (err) {
      assert(
        err.message.includes("failed to load SDK"),
        `Expected SDK load error, got: ${err.message}`
      )
      assert(
        err.message.includes("Make sure it is installed"),
        `Expected install hint, got: ${err.message}`
      )
    }
  }),

  test("createAtlasProvider loads policy from policyFile", async () => {
    const { writeFileSync, unlinkSync } = await import("fs")
    const { join } = await import("path")
    const tmpFile = join(process.cwd(), "_test_policy.json")
    const testPolicy = { type: "dstack_tdx", allowed_tcb_status: ["UpToDate"] }

    try {
      writeFileSync(tmpFile, JSON.stringify(testPolicy), "utf-8")
      const mod = await import("../dist/index.js")
      // This will throw for missing SDK, but the policy resolution should succeed
      // We verify the policy was loaded by checking the error is about SDK, not policy
      try {
        mod.createAtlasProvider({
          sdk: "@nonexistent/sdk-that-does-not-exist",
          baseURL: "https://example.com/v1",
          policyFile: tmpFile,
        })
        throw new Error("Should have thrown")
      } catch (err) {
        assert(
          err.message.includes("failed to load SDK"),
          `Expected SDK error (policy should have loaded), got: ${err.message}`
        )
      }
    } finally {
      try { unlinkSync(tmpFile) } catch {}
    }
  }),

  test("createAtlasProvider throws for nonexistent policyFile", async () => {
    const mod = await import("../dist/index.js")
    try {
      mod.createAtlasProvider({
        sdk: "@ai-sdk/openai-compatible",
        baseURL: "https://example.com/v1",
        policyFile: "/nonexistent/path/policy.json",
      })
      throw new Error("Should have thrown")
    } catch (err) {
      assert(
        err.message.includes("failed to read policy file"),
        `Expected policy file error, got: ${err.message}`
      )
    }
  }),

  test("host discovers createAtlasProvider via create* convention", async () => {
    const mod = await import("../dist/index.js")
    const createFnKey = Object.keys(mod).find((k) => k.startsWith("create"))
    assert(createFnKey === "createAtlasProvider", `Expected createAtlasProvider, got: ${createFnKey}`)
  }),
]

// ============================================================================
// Integration tests — aTLS policy verification against vllm.concrete-security.com
// ============================================================================

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
  os_image_hash:
    "86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a",
  app_compose: mergeWithDefaultAppCompose({
    docker_compose_file: VLLM_DOCKER_COMPOSE,
    allowed_envs: ["EKM_SHARED_SECRET", "AUTH_SERVICE_TOKEN"],
  }),
  allowed_tcb_status: ["UpToDate", "SWHardeningNeeded"],
}

const TARGET = "vllm.concrete-security.com"
const INTEGRATION_TIMEOUT_MS = 30_000

const integrationTests = [
  test("correct policy connects and returns models", async () => {
    const ac = new AbortController()
    const timer = setTimeout(() => ac.abort(), INTEGRATION_TIMEOUT_MS)

    try {
      const fetch = createAtlsFetch({ target: TARGET, policy: VLLM_POLICY })
      const response = await fetch("/v1/models", { signal: ac.signal })

      assert(response.ok === true, `Expected response.ok, got status ${response.status}`)
      assert(
        response.attestation?.trusted === true,
        `Expected attestation.trusted === true, got ${response.attestation?.trusted}`
      )
      assert(
        response.attestation?.teeType === "tdx",
        `Expected teeType "tdx", got "${response.attestation?.teeType}"`
      )
      // tcbStatus is only present after a real aTLS handshake (not plain TLS)
      assert(
        typeof response.attestation?.tcbStatus === "string" && response.attestation.tcbStatus.length > 0,
        `Expected non-empty tcbStatus from aTLS handshake, got "${response.attestation?.tcbStatus}"`
      )

      const data = await response.json()
      assert(Array.isArray(data.data), `Expected data.data to be an array, got ${typeof data.data}`)
      assert(data.data.length > 0, "Expected at least one model in the list")
    } finally {
      clearTimeout(timer)
    }
  }),

  test("altered mrtd policy rejects connection", async () => {
    const badPolicy = {
      ...VLLM_POLICY,
      expected_bootchain: {
        ...VLLM_POLICY.expected_bootchain,
        // Flip one character in mrtd to make it invalid
        mrtd: "a" + VLLM_POLICY.expected_bootchain.mrtd.slice(1),
      },
    }

    const ac = new AbortController()
    const timer = setTimeout(() => ac.abort(), INTEGRATION_TIMEOUT_MS)

    try {
      const fetch = createAtlsFetch({ target: TARGET, policy: badPolicy })
      await fetch("/v1/models", { signal: ac.signal })
      throw new Error("Should have thrown due to bad policy")
    } catch (err) {
      assert(
        err.message !== "Should have thrown due to bad policy",
        "fetch should have thrown before reaching this point"
      )
      const msg = err.message.toLowerCase()
      assert(
        msg.includes("mismatch") || msg.includes("handshake") || msg.includes("verification") || msg.includes("attestation"),
        `Expected attestation/handshake error, got: ${err.message}`
      )
    } finally {
      clearTimeout(timer)
    }
  }),
]

// ============================================================================
// Main
// ============================================================================

async function main() {
  console.log("private-ai-sdk tests\n")

  console.log("Unit tests\n================================\n")
  for (const runTest of tests) {
    await runTest()
  }

  console.log("\nIntegration tests (aTLS → vllm.concrete-security.com)\n================================\n")
  for (const runTest of integrationTests) {
    await runTest()
  }

  console.log("\n================================")
  console.log(`Results: ${passed} passed, ${failed} failed`)

  await closeAllSockets()
  process.exit(failed > 0 ? 1 : 0)
}

main().catch(async (err) => {
  console.error("Fatal error:", err)
  await closeAllSockets()
  process.exit(1)
})
