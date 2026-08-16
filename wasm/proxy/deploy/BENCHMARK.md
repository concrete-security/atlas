# RA-TLS Proxy Benchmark

Benchmark comparing latency and throughput for different connection scenarios to a TEE-hosted vLLM server.

## Scenarios

| Scenario | Description | Implementation |
|----------|-------------|----------------|
| **Standard TLS** | Direct HTTPS connection to TEE | Node.js built-in |
| **TLS + Proxy** | WebSocket tunnel, no attestation | Node.js built-in TLS |
| **RA-TLS** | Direct RA-TLS connection (full attestation) | ratls-node |
| **RA-TLS + Proxy** | WebSocket tunnel with full attestation | ratls-wasm |

## Usage

```bash
# Prerequisites
cd wasm/proxy/deploy
npm install ws  # WebSocket library

# Run benchmark (default 5 iterations)
node benchmark.mjs

# Run with custom iterations
node benchmark.mjs 10
```

### Configuration

Edit the constants at the top of `benchmark.mjs`:

```javascript
const VLLM_HOST = 'vllm.concrete-security.com';
const VLLM_PORT = 443;
const PROXY_URL = 'ws://your-proxy-host:9000/tunnel';
```

## Results

Test configuration:
- **Target**: vLLM server in TDX TEE (`vllm.concrete-security.com`)
- **Proxy**: EC2 instance in us-west-1 (`ws://ec2-13-56-181-124.us-west-1.compute.amazonaws.com:9000`)
- **Request**: Chat completion, 200 output tokens
- **Iterations**: 10

### Latency & Throughput

| Metric | Standard TLS | TLS + Proxy | RA-TLS | RA-TLS + Proxy |
|--------|--------------|-------------|--------|----------------|
| TTFT mean | 608ms | 1332ms | 4813ms | 4985ms |
| TTFT p50 | 588ms | 1337ms | 4719ms | 5078ms |
| TTFT p95 | 797ms | 1362ms | 6408ms | 7148ms |
| Eff. Throughput | 157.1 t/s | 104.0 t/s | 37.0 t/s | 36.7 t/s |
| Gen. Throughput | 301.4 t/s | 338.4 t/s | 306.5 t/s | 342.4 t/s |
| Total time mean | 1277ms | 1923ms | 5467ms | 5571ms |
| Attestation mean | N/A | N/A | 4130ms | 4225ms |

### Overhead Analysis

| Comparison | Overhead | Notes |
|------------|----------|-------|
| **Proxy overhead** (TLS+Proxy - Standard) | **+724ms** | Same implementation, fair comparison |
| **RA-TLS overhead** (RA-TLS - Standard) | **+4205ms** | Attestation cost (quote + collateral + verification) |
| RA-TLS+Proxy overhead (RA-TLS+Proxy - Standard) | +4377ms | Different implementation (ratls-wasm) |

**Note**: RA-TLS and RA-TLS+Proxy use different libraries (ratls-node vs ratls-wasm), so direct comparison is not apples-to-apples. The proxy overhead (~724ms) is best measured from Standard TLS vs TLS+Proxy.

## Key Findings

1. **Proxy overhead is ~724ms** — measured by comparing Standard TLS vs TLS + Proxy (same implementation)

2. **RA-TLS attestation adds ~4.2 seconds** to TTFT, which includes:
   - TLS handshake
   - Quote fetch from TEE (~3s) - hardware TDX operation
   - Collateral fetch from Intel PCCS (~1s)
   - DCAP quote verification

3. **Generation throughput is identical** (~300-340 t/s) across all scenarios — overhead only affects connection setup (TTFT)

4. **Effective throughput** (tokens/total_time) is lower for RA-TLS due to TTFT overhead, but **generation throughput** (excluding TTFT) is unchanged

## Implementation Note

RA-TLS and RA-TLS + Proxy use different libraries:
- **RA-TLS**: ratls-node (native, direct TCP)
- **RA-TLS + Proxy**: ratls-wasm (WebAssembly, WebSocket transport)

Both perform full DCAP attestation. Direct comparison between them includes implementation differences, not just proxy overhead. The proxy overhead is best measured from the Standard TLS vs TLS + Proxy comparison.

## Notes

- The proxy connection uses `ws://` (unencrypted); in production with Caddy, use `wss://`
- Quote generation time varies (~3-4s) as it's a hardware operation in the TDX module
- Collateral is fetched from Intel PCCS on each connection (could be cached for optimization)
