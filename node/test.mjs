/**
 * aTLS Node.js Tests
 *
 * Run with: npm test
 */

import { createAtlsAgent, createAtlsFetch, mergeWithDefaultAppCompose } from "./atls-fetch.js"
import { createRequire } from "module"
import { readFileSync } from "fs"
import { dirname, join } from "path"
import { fileURLToPath } from "url"

const require = createRequire(import.meta.url)
const binding = require("./index.cjs")

const __dirname = dirname(fileURLToPath(import.meta.url))

// Read docker compose content from core test data
const VLLM_DOCKER_COMPOSE = readFileSync(
  join(__dirname, "../core/tests/data/vllm_docker_compose.yml"),
  "utf-8"
)

// Full production policy for vllm.concrete-security.com
const VLLM_POLICY = {
  type: "dstack_tdx",
  expected_bootchain: {
    mrtd: "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
    rtmr0: "24c15e08c07aa01c531cbd7e8ba28f8cb62e78f6171bf6a8e0800714a65dd5efd3a06bf0cf5433c02bbfac839434b418",
    rtmr1: "6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7",
    rtmr2: "89e73cedf48f976ffebe8ac1129790ff59a0f52d54d969cb73455b1a79793f1dc16edc3b1fccc0fd65ea5905774bbd57"
  },
  os_image_hash: "86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a",
  app_compose: mergeWithDefaultAppCompose({
    docker_compose_file: VLLM_DOCKER_COMPOSE,
    allowed_envs: ["EKM_SHARED_SECRET", "AUTH_SERVICE_TOKEN"]
  }),
  allowed_tcb_status: ["UpToDate", "SWHardeningNeeded"]
}

// Dev policy for tests that don't need full verification
const DEV_POLICY = {
  type: "dstack_tdx",
  disable_runtime_verification: true,
  allowed_tcb_status: ["UpToDate", "SWHardeningNeeded", "OutOfDate"]
}

// Test helpers
let passed = 0
let failed = 0

function test(name, fn) {
  return async () => {
    try {
      await fn()
      console.log(`✓ ${name}`)
      passed++
    } catch (err) {
      console.error(`✗ ${name}`)
      console.error(`  Error: ${err.message}`)
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
  test("Module imports successfully", async () => {
    assert(typeof createAtlsAgent === "function", "createAtlsAgent not exported")
    assert(typeof createAtlsFetch === "function", "createAtlsFetch not exported")
    assert(typeof mergeWithDefaultAppCompose === "function", "mergeWithDefaultAppCompose not exported")
  }),

  test("Native binding loads", async () => {
    assert(binding, "Binding not loaded")
    assert(typeof binding.atlsConnect === "function", "atlsConnect function not available")
    assert(typeof binding.mergeWithDefaultAppCompose === "function", "mergeWithDefaultAppCompose function not available")
  }),

  test("Socket API available", async () => {
    assert(typeof binding.atlsConnect === "function", "atlsConnect not available")
    assert(typeof binding.socketRead === "function", "socketRead not available")
    assert(typeof binding.socketWrite === "function", "socketWrite not available")
    assert(typeof binding.socketClose === "function", "socketClose not available")
    assert(typeof binding.socketDestroy === "function", "socketDestroy not available")
    assert(typeof binding.closeAllSockets === "function", "closeAllSockets not available")
  }),

  test("createAtlsFetch requires policy", async () => {
    try {
      createAtlsFetch({ target: "example.com" })
      throw new Error("Should have thrown")
    } catch (err) {
      assert(err.message.includes("policy is required"), `Expected policy error, got: ${err.message}`)
    }
  }),

  test("createAtlsFetch rejects string shorthand", async () => {
    try {
      createAtlsFetch("example.com")
      throw new Error("Should have thrown")
    } catch (err) {
      assert(err.message.includes("String shorthand no longer supported"), `Expected string error, got: ${err.message}`)
    }
  }),

  test("createAtlsAgent requires policy", async () => {
    try {
      createAtlsAgent({ target: "example.com" })
      throw new Error("Should have thrown")
    } catch (err) {
      assert(err.message.includes("policy is required"), `Expected policy error, got: ${err.message}`)
    }
  }),

  test("createAtlsAgent rejects string shorthand", async () => {
    try {
      createAtlsAgent("example.com")
      throw new Error("Should have thrown")
    } catch (err) {
      assert(err.message.includes("String shorthand no longer supported"), `Expected string error, got: ${err.message}`)
    }
  }),

  test("createAtlsAgent error handling - missing target", async () => {
    try {
      createAtlsAgent({ policy: DEV_POLICY })
      throw new Error("Should have thrown error for missing target")
    } catch (err) {
      assert(err.message.includes("target is required"), `Wrong error: ${err.message}`)
    }
  }),

  test("createAtlsAgent with valid options", async () => {
    const agent = createAtlsAgent({
      target: "example.com:443",
      policy: DEV_POLICY,
      onAttestation: (att) => {}
    })
    assert(typeof agent === "object", "Agent not an object")
    assert(typeof agent.createConnection === "function", "Agent missing createConnection method")
  }),

  test("createAtlsAgent with serverName override", async () => {
    const agent = createAtlsAgent({
      target: "10.0.0.1:443",
      serverName: "example.com",
      policy: DEV_POLICY
    })
    assert(typeof agent === "object", "Agent not an object")
  }),

  test("createAtlsFetch with valid options", async () => {
    const fetch = createAtlsFetch({
      target: "example.com:443",
      policy: DEV_POLICY,
      onAttestation: (att) => {}
    })
    assert(typeof fetch === "function", "Fetch not a function")
  }),

  test("createAtlsFetch returns promises", async () => {
    const fetch = createAtlsFetch({
      target: "example.com",
      policy: DEV_POLICY
    })

    const p1 = fetch("/api/data", { method: "GET" })
    const p2 = fetch("https://example.com/api/data", { method: "GET" })

    assert(p1 instanceof Promise, "Fetch should return a Promise for relative URL")
    assert(p2 instanceof Promise, "Fetch should return a Promise for absolute URL")

    // Suppress unhandled rejection warnings
    p1.catch(() => {})
    p2.catch(() => {})
  }),

  test("mergeWithDefaultAppCompose fills in defaults", async () => {
    const merged = mergeWithDefaultAppCompose({
      docker_compose_file: "test",
      allowed_envs: ["MY_VAR"]
    })

    assert(merged.docker_compose_file === "test", "User value should be preserved")
    assert(Array.isArray(merged.allowed_envs) && merged.allowed_envs[0] === "MY_VAR", "User allowed_envs should be preserved")
    assert(merged.runner === "docker-compose", "Default runner should be filled in")
    assert(merged.manifest_version === 2, "Default manifest_version should be filled in")
    assert(merged.features?.includes("kms"), "Default features should be filled in")
  }),

  test("mergeWithDefaultAppCompose preserves user overrides", async () => {
    const merged = mergeWithDefaultAppCompose({
      docker_compose_file: "custom-compose",
      runner: "custom-runner",
      features: ["custom-feature"]
    })

    assert(merged.docker_compose_file === "custom-compose", "docker_compose_file should be preserved")
    assert(merged.runner === "custom-runner", "User runner should override default")
    assert(merged.features[0] === "custom-feature", "User features should override default")
  }),

  test("Main entry point exports high-level API", async () => {
    const mainExports = await import("./atls-fetch.js")
    assert(typeof mainExports.createAtlsFetch === "function", "createAtlsFetch not exported")
    assert(typeof mainExports.createAtlsAgent === "function", "createAtlsAgent not exported")
    assert(typeof mainExports.mergeWithDefaultAppCompose === "function", "mergeWithDefaultAppCompose not exported")
  }),

  test("full verification against vllm.concrete-security.com", async () => {
    const fetch = createAtlsFetch({
      target: "vllm.concrete-security.com",
      policy: VLLM_POLICY,
      onAttestation: (att) => {
        console.log(`  Attestation received: teeType=${att.teeType}, trusted=${att.trusted}`)
      }
    })

    const response = await fetch("/v1/models")

    assert(response.ok, `Expected 200, got ${response.status}`)
    assert(response.attestation, "Response should have attestation")
    assert(response.attestation.trusted, "Attestation should be trusted")
    assert(response.attestation.teeType === "tdx", `Expected teeType=tdx, got ${response.attestation.teeType}`)

    const data = await response.json()
    assert(data.data && Array.isArray(data.data), "Should return models list")
    console.log(`  Models: ${data.data.map(m => m.id).join(", ")}`)
  })
]

// ============================================================================
// Main
// ============================================================================

async function main() {
  console.log("aTLS Node.js Tests\n")
  console.log("================================\n")

  for (const runTest of tests) {
    await runTest()
  }

  console.log("\n================================")
  console.log(`Results: ${passed} passed, ${failed} failed`)

  // Gracefully close all sockets before exiting
  await binding.closeAllSockets()

  process.exit(failed > 0 ? 1 : 0)
}

main().catch(err => {
  console.error("Fatal error:", err)
  process.exit(1)
})
