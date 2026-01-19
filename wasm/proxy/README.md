# proxy (byte forwarder)

WebSocket (and later WebTransport) to TCP bridge that forwards raw bytes to the TEE. Does not terminate inner TLS.

## Configuration

The proxy uses environment variables for configuration:

- `RATLS_PROXY_LISTEN`: Address to listen on (default: `127.0.0.1:9000`)
- `RATLS_PROXY_TARGET`: Default target host:port (default: `127.0.0.1:8443`)
- `RATLS_PROXY_ALLOWLIST`: Comma-separated list of authorized target hosts/ports (required)

## Security

The proxy enforces an allowlist of permitted target hosts/ports to prevent SSRF attacks. Any target (whether from the default configuration or from the `?target=host:port` query parameter) must be explicitly authorized in the allowlist, or the connection will be rejected.

**Important**: If `RATLS_PROXY_ALLOWLIST` is not set or empty, all targets will be rejected and the proxy will fail to start.

Example:
```bash
RATLS_PROXY_ALLOWLIST="vllm.concrete-security.com:443,192.168.1.100:8443" ./ratls-proxy
```

## Requirements
- Endpoints: `wss://proxy/tunnel?target=host:port`; optional WebTransport stream mapping to TCP.
- AuthN/AuthZ (JWT or mTLS) plus destination ACL to prevent SSRF.
- Origin allowlist for browser clients, idle timeouts, backpressure, and metrics (connects, bytes, duration).

## Deployment

### Quick Start (AWS/Ubuntu)

1. Launch an EC2 instance (Ubuntu 24.04, t3.medium recommended)
2. Configure security groups: SSH (22), HTTP (80), HTTPS (443)
3. Point your domain DNS to the instance IP
4. Run the setup script:

```bash
git clone <your-repo-url> secure-channel
cd secure-channel/wasm/proxy/deploy
sudo ./setup.sh proxy.yourdomain.com tee.backend.com:443
```

This installs Caddy (for TLS), builds the proxy, and configures systemd services.

### Docker Deployment

Build and run the container:

```bash
# Build from repository root
docker build -t ratls-proxy -f wasm/proxy/Dockerfile .

# Run with required environment variables
docker run -d \
  -e RATLS_PROXY_ALLOWLIST="tee.backend.com:443" \
  -e RATLS_PROXY_TARGET="tee.backend.com:443" \
  -p 9000:9000 \
  ratls-proxy
```

For production, place behind a reverse proxy (Caddy/nginx) for TLS termination.

### Manual Deployment

See `deploy/` directory for:
- `ratls-proxy.service` - systemd unit file
- `Caddyfile` - Caddy reverse proxy template
- `setup.sh` - automated setup script
- `benchmark.sh` - performance comparison script

### Configuration Files

After running `setup.sh`, configuration is stored in:
- `/etc/ratls-proxy/env` - environment variables
- `/etc/caddy/Caddyfile` - reverse proxy config

Edit and restart:
```bash
sudo nano /etc/ratls-proxy/env
sudo systemctl restart ratls-proxy
```

## Benchmarking

Compare direct vs proxy latency:

```bash
./deploy/benchmark.sh https://tee.backend.com:443 wss://proxy.yourdomain.com/tunnel 50
```

Metrics collected:
- TCP connection time
- TLS handshake time
- Total request latency
- p50/p95/p99 percentiles
