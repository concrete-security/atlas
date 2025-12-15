import { createRatlsAgent, createRatlsFetch } from "./ratls-fetch.js"
import { createRequire } from "module"

const require = createRequire(import.meta.url)
const binding = require("./index.cjs")

console.log("Testing ratls-node module...\n")

let testsPassed = 0
let testsFailed = 0

function test(name, fn) {
  try {
    fn()
    console.log(`✓ ${name}`)
    testsPassed++
  } catch (error) {
    console.error(`✗ ${name}: ${error.message}`)
    testsFailed++
  }
}

try {
  test("Module imports successfully", () => {
    if (!createRatlsAgent) throw new Error("createRatlsAgent not exported")
  })

  test("Native binding loads", () => {
    if (!binding) throw new Error("Binding not loaded")
    if (typeof binding.ratlsConnect !== "function") {
      throw new Error("ratlsConnect function not available")
    }
  })

  test("createRatlsAgent with string target", () => {
    const agent = createRatlsAgent("example.com")
    if (typeof agent !== "object") throw new Error("Agent not an object")
    if (typeof agent.createConnection !== "function") {
      throw new Error("Agent missing createConnection method")
    }
  })

  test("createRatlsAgent with options object", () => {
    let attestationCalled = false
    const agent = createRatlsAgent({
      target: "example.com:443",
      onAttestation: (att) => {
        attestationCalled = true
      }
    })
    if (typeof agent !== "object") throw new Error("Agent not an object")
  })

  test("createRatlsAgent with port in target", () => {
    const agent = createRatlsAgent("example.com:8443")
    if (typeof agent !== "object") throw new Error("Agent not an object")
  })

  test("createRatlsAgent with serverName override", () => {
    const agent = createRatlsAgent({
      target: "10.0.0.1:443",
      serverName: "example.com"
    })
    if (typeof agent !== "object") throw new Error("Agent not an object")
  })

  test("createRatlsAgent error handling - missing target", () => {
    try {
      createRatlsAgent({})
      throw new Error("Should have thrown error for missing target")
    } catch (e) {
      if (!e.message.includes("target is required")) {
        throw new Error(`Wrong error: ${e.message}`)
      }
    }
  })

  test("createRatlsFetch with string target", () => {
    const fetch = createRatlsFetch("example.com")
    if (typeof fetch !== "function") throw new Error("Fetch not a function")
  })

  test("createRatlsFetch with options object", () => {
    const fetch = createRatlsFetch({
      target: "example.com:443",
      onAttestation: (att) => {}
    })
    if (typeof fetch !== "function") throw new Error("Fetch not a function")
  })

  test("createRatlsFetch hybrid routing - accepts relative and absolute URLs", () => {
    const fetch = createRatlsFetch("example.com")
    if (typeof fetch !== "function") throw new Error("Fetch not a function")
    
    const relativeUrl = "/api/data"
    const absoluteUrl = "https://example.com/api/data"
    const otherHostUrl = "https://google.com"
    
    const p1 = fetch(relativeUrl, { method: "GET" })
    const p2 = fetch(absoluteUrl, { method: "GET" })
    const p3 = fetch(otherHostUrl, { method: "GET" })
    
    if (!(p1 instanceof Promise)) throw new Error("Fetch should return a Promise")
    if (!(p2 instanceof Promise)) throw new Error("Fetch should return a Promise")
    if (!(p3 instanceof Promise)) throw new Error("Fetch should return a Promise")
    
    p1.catch(() => {})
    p2.catch(() => {})
    p3.catch(() => {})
  })

  test("Socket API available", () => {
    const hasSocketApi =
      typeof binding.ratlsConnect === "function" &&
      typeof binding.socketRead === "function" &&
      typeof binding.socketWrite === "function" &&
      typeof binding.socketClose === "function" &&
      typeof binding.socketDestroy === "function"
    if (!hasSocketApi) {
      throw new Error("Socket API not fully available")
    }
  })

  test("Low-level bindings available from binding export", () => {
    const bindingExports = require("./index.cjs")
    if (typeof bindingExports.ratlsConnect !== "function") {
      throw new Error("ratlsConnect not exported from index.js")
    }
    if (typeof bindingExports.socketRead !== "function") {
      throw new Error("socketRead not exported from index.js")
    }
    if (typeof bindingExports.socketWrite !== "function") {
      throw new Error("socketWrite not exported from index.js")
    }
    if (typeof bindingExports.socketClose !== "function") {
      throw new Error("socketClose not exported from index.js")
    }
    if (typeof bindingExports.socketDestroy !== "function") {
      throw new Error("socketDestroy not exported from index.js")
    }
  })

  test("Main entry point only exports high-level API", async () => {
    const mainExports = await import("./ratls-fetch.js")
    if (typeof mainExports.createRatlsFetch !== "function") {
      throw new Error("createRatlsFetch not exported from ratls-fetch.js")
    }
    if (typeof mainExports.ratlsConnect === "function") {
      throw new Error("ratlsConnect should not be exported from main entry point - use 'ratls-node/binding' instead")
    }
  })

  console.log(`\n✅ Tests passed: ${testsPassed}`)
  if (testsFailed > 0) {
    console.error(`❌ Tests failed: ${testsFailed}`)
    process.exit(1)
  }

  console.log("\nNote: Full functionality test requires a valid TEE endpoint.")
  console.log("Run: node examples/ai-sdk-openai-demo.mjs for end-to-end test.")

} catch (error) {
  console.error("❌ Test suite failed:", error.message)
  console.error(error.stack)
  process.exit(1)
}
