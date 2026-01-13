# Multi-stage build for ratls-proxy
# Build: docker build -t ratls-proxy .
# Run: docker run -e RATLS_PROXY_ALLOWLIST=host:port -p 9000:9000 ratls-proxy

FROM rust:1.75-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace files needed for building
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY wasm/proxy ./wasm/proxy

# Build only the proxy binary
RUN cargo build -p ratls-proxy --release

# Runtime stage - minimal image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/target/release/ratls-proxy /usr/local/bin/

# Default environment variables
ENV RATLS_PROXY_LISTEN=0.0.0.0:9000
ENV RATLS_PROXY_TARGET=127.0.0.1:8443
# RATLS_PROXY_ALLOWLIST must be set at runtime

EXPOSE 9000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD nc -z localhost 9000 || exit 1

CMD ["ratls-proxy"]
