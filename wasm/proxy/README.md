# proxy (byte forwarder)

WebSocket (and later WebTransport) to TCP bridge that forwards raw bytes to the TEE. Does not terminate inner TLS.

## Configuration

The proxy uses environment variables for configuration:

- `ATLS_PROXY_LISTEN`: Address to listen on (default: `127.0.0.1:9000`)
- `ATLS_PROXY_TARGET`: Default target host:port (default: `127.0.0.1:8443`)
- `ATLS_PROXY_ALLOWLIST`: Comma-separated list of authorized target hosts/ports (required)

## Security

The proxy enforces an allowlist of permitted target hosts/ports to prevent SSRF attacks. Any target (whether from the default configuration or from the `?target=host:port` query parameter) must be explicitly authorized in the allowlist, or the connection will be rejected.

**Important**: If `ATLS_PROXY_ALLOWLIST` is not set or empty, all targets will be rejected and the proxy will fail to start.

Example:
```bash
ATLS_PROXY_ALLOWLIST="vllm.concrete-security.com:443,192.168.1.100:8443" ./atls-proxy
```

## Requirements
- Endpoints: `wss://proxy/tunnel?target=host:port`; optional WebTransport stream mapping to TCP.
- AuthN/AuthZ (JWT or mTLS) plus destination ACL to prevent SSRF.
- Origin allowlist for browser clients, idle timeouts, backpressure, and metrics (connects, bytes, duration).
