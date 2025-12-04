import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { createRequire } from "node:module"

const require = createRequire(import.meta.url)
const __dirname = path.dirname(fileURLToPath(import.meta.url))

/**
 * Platform-specific package mappings for @napi-rs/cli built packages
 */
const platformPackages = {
  "darwin-arm64": "@ratls-node/darwin-arm64",
  "darwin-x64": "@ratls-node/darwin-x64",
  "linux-arm64-gnu": "@ratls-node/linux-arm64-gnu",
  "linux-arm64-musl": "@ratls-node/linux-arm64-musl",
  "linux-x64-gnu": "@ratls-node/linux-x64-gnu",
  "linux-x64-musl": "@ratls-node/linux-x64-musl",
  "win32-x64-msvc": "@ratls-node/win32-x64-msvc",
}

/**
 * Detect if running on musl libc (Alpine, etc.)
 */
function isMusl() {
  if (process.platform !== "linux") return false
  try {
    // Check if /etc/alpine-release exists (Alpine Linux)
    if (fs.existsSync("/etc/alpine-release")) return true
    // Check ldd output for musl
    const { execSync } = require("child_process")
    const lddOutput = execSync("ldd --version 2>&1 || true", { encoding: "utf8" })
    return lddOutput.includes("musl")
  } catch {
    return false
  }
}

/**
 * Get the platform key for the current system
 */
function getPlatformKey() {
  const platform = process.platform
  const arch = process.arch

  if (platform === "darwin") {
    return arch === "arm64" ? "darwin-arm64" : "darwin-x64"
  }
  if (platform === "win32") {
    return "win32-x64-msvc"
  }
  if (platform === "linux") {
    const libc = isMusl() ? "musl" : "gnu"
    return arch === "arm64" ? `linux-arm64-${libc}` : `linux-x64-${libc}`
  }
  throw new Error(`Unsupported platform: ${platform}-${arch}`)
}

/**
 * Try to load the native module from an npm package
 */
function tryLoadFromPackage() {
  const platformKey = getPlatformKey()
  const packageName = platformPackages[platformKey]

  if (!packageName) {
    return null
  }

  try {
    return require(packageName)
  } catch {
    return null
  }
}

/**
 * Try to load the native module from local build (development)
 */
function tryLoadFromLocal() {
  const envPath = process.env.RATLS_NODE_BINARY
  if (envPath && fs.existsSync(envPath)) {
    return require(envPath)
  }

  const platformLib =
    process.platform === "win32"
      ? "ratls_node.dll"
      : process.platform === "darwin"
        ? "libratls_node.dylib"
        : "libratls_node.so"

  // Check for napi-rs built .node file first (from `napi build`)
  const napiNodeFile = path.resolve(__dirname, "ratls-node.node")
  if (fs.existsSync(napiNodeFile)) {
    return require(napiNodeFile)
  }

  // Then check target directories
  const releasePath = path.resolve(__dirname, "../target/release/ratls_node.node")
  const debugPath = path.resolve(__dirname, "../target/debug/ratls_node.node")
  const releaseLib = path.resolve(__dirname, "../target/release", platformLib)
  const debugLib = path.resolve(__dirname, "../target/debug", platformLib)

  // Try to create .node from .dylib/.so/.dll
  for (const [nodePath, libPath] of [
    [releasePath, releaseLib],
    [debugPath, debugLib],
  ]) {
    if (fs.existsSync(libPath)) {
      try {
        if (fs.existsSync(nodePath)) fs.rmSync(nodePath)
        fs.copyFileSync(libPath, nodePath)
        return require(nodePath)
      } catch {
        try {
          fs.symlinkSync(libPath, nodePath)
          return require(nodePath)
        } catch {
          // Continue to next candidate
        }
      }
    }
    if (fs.existsSync(nodePath)) {
      return require(nodePath)
    }
  }

  return null
}

/**
 * Load the native module
 */
function loadBinding() {
  // First try npm package (production)
  const fromPackage = tryLoadFromPackage()
  if (fromPackage) return fromPackage

  // Then try local build (development)
  const fromLocal = tryLoadFromLocal()
  if (fromLocal) return fromLocal

  // Provide helpful error message
  const platformKey = getPlatformKey()
  const packageName = platformPackages[platformKey]

  throw new Error(
    `Failed to load ratls-node native module.

For production: Install the platform-specific package:
  npm install ${packageName}

For development: Build from source:
  cargo build -p ratls-node --release

Or use @napi-rs/cli:
  cd node && pnpm install && pnpm build`
  )
}

const binding = loadBinding()

export default binding
export const httpRequest = binding.httpRequest
export const httpStreamRequest = binding.httpStreamRequest
export const streamRead = binding.streamRead
export const streamClose = binding.streamClose
