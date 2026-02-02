# atlas-proxy

WebSocket-to-TCP bridge for browser-based aTLS connections. Forwards raw bytes between browser WebSocket connections and TEE TCP endpoints.

**Key Characteristics:**
- Byte-level forwarding (no TLS termination)
- No access to encrypted traffic
- All attestation verification happens in the browser
- Required for browser deployments (browsers cannot make raw TCP connections)

## Quick Start

```bash
# Set required allowlist and start proxy
export ATLS_PROXY_ALLOWLIST="vllm.example.com:443,tee2.example.com:8443"
export ATLS_PROXY_LISTEN="127.0.0.1:9000"

cargo run -p atlas-proxy
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ATLS_PROXY_LISTEN` | Address and port to listen on | `127.0.0.1:9000` | No |
| `ATLS_PROXY_TARGET` | Default target endpoint | `127.0.0.1:8443` | No |
| `ATLS_PROXY_ALLOWLIST` | Comma-separated list of allowed targets | None | **Yes** |

### Configuration Examples

#### Development (Local Testing)

```bash
# Allow connections to local TEE and production endpoint
export ATLS_PROXY_ALLOWLIST="localhost:8443,vllm.concrete-security.com:443"
export ATLS_PROXY_LISTEN="127.0.0.1:9000"

cargo run -p atlas-proxy
```

#### Production (Public Proxy)

```bash
# Listen on all interfaces, restrict to production TEEs
export ATLS_PROXY_ALLOWLIST="tee1.example.com:443,tee2.example.com:443"
export ATLS_PROXY_LISTEN="0.0.0.0:9000"

# In production, consider:
# - Running behind reverse proxy (nginx, caddy) for TLS termination
# - Using systemd/docker for process management
# - Implementing rate limiting and monitoring

cargo run --release -p atlas-proxy
```

#### Multiple Endpoints

```bash
# Allow multiple TEE endpoints on different ports
export ATLS_PROXY_ALLOWLIST="tee1.example.com:443,tee1.example.com:8443,tee2.example.com:443"
export ATLS_PROXY_LISTEN="0.0.0.0:9000"

cargo run -p atlas-proxy
```

### Client Configuration

Browser clients specify the target via query parameters:

```javascript
import { createAtlsFetch } from "@concrete-security/atlas-wasm"

// Target specified in proxyUrl query string
const fetch = createAtlsFetch({
  proxyUrl: "ws://127.0.0.1:9000?target=vllm.example.com:443",
  targetHost: "vllm.example.com"
})
```

Or via the target host configuration:

```javascript
// Uses ATLS_PROXY_TARGET default if not specified in URL
const fetch = createAtlsFetch({
  proxyUrl: "ws://127.0.0.1:9000",
  targetHost: "vllm.example.com"  // Must be in allowlist
})
```

## Security

### Allowlist Enforcement

**Critical**: The allowlist prevents Server-Side Request Forgery (SSRF) attacks where malicious clients could use the proxy to access internal network resources.

**How it works:**
1. Client requests connection to target (via query param or default)
2. Proxy checks if target is in `ATLS_PROXY_ALLOWLIST`
3. If not allowed → connection rejected
4. If allowed → WebSocket tunnel established

```
Browser                     Proxy                       TEE
   │                          │                          │
   │─── ws://proxy?target=X ─►│                          │
   │                          │─ Check allowlist         │
   │                          │  ✓ Allowed: forward      │
   │                          │  ✗ Denied: reject        │
   │                          │                          │
   │                          │──── TCP connect ────────►│
   │◄──── Encrypted tunnel (TLS inside WebSocket) ──────►│
```

### Attack Prevention

| Attack Vector | Mitigation |
|---------------|------------|
| SSRF to internal services | Allowlist enforcement |
| Traffic inspection | Proxy cannot decrypt TLS (end-to-end encryption) |
| Attestation replay | Session binding via EKM (handled in browser) |

### Production Security Checklist

- [ ] Allowlist contains only authorized TEE endpoints
- [ ] Proxy runs with minimal privileges (non-root user)
- [ ] Firewall rules restrict proxy's outbound connections
- [ ] Monitoring for connection patterns and failures
- [ ] Rate limiting to prevent abuse (implement at reverse proxy level)
- [ ] TLS termination at reverse proxy (wss:// instead of ws://)
- [ ] Authentication for proxy access (implement at reverse proxy level)
- [ ] Regular security updates for dependencies

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Browser                          │
│  ┌──────────────────────────────────────────────┐  │
│  │  WASM (atlas_wasm)                           │  │
│  │  - TLS 1.3 client                            │  │
│  │  - Attestation verification                  │  │
│  │  - HTTP/1.1 protocol handling                │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────┬───────────────────────────────────┘
                  │ WebSocket (encrypted TLS data)
                  │
┌─────────────────▼───────────────────────────────────┐
│               Proxy (atlas-proxy)                    │
│  - WebSocket server                                  │
│  - Allowlist enforcement                             │
│  - Byte forwarding only (no decrypt)                │
└─────────────────┬───────────────────────────────────┘
                  │ TCP (encrypted TLS data)
                  │
┌─────────────────▼───────────────────────────────────┐
│                    TEE Endpoint                      │
│  - TLS 1.3 server                                    │
│  - Quote generation                                  │
│  - Application (vLLM, etc.)                          │
└─────────────────────────────────────────────────────┘
```

**Key Points:**
- Proxy never sees plaintext (TLS is end-to-end from browser to TEE)
- Proxy only enforces allowlist and forwards bytes
- All security-critical operations happen in browser WASM or TEE

## See Also

- [wasm/README.md](../README.md) - WASM binding documentation
- [core/README.md](../../core/README.md) - aTLS protocol specification
