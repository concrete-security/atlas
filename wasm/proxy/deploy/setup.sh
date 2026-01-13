#!/bin/bash
# One-command setup script for ratls-proxy on Ubuntu/Debian
# Usage: sudo ./setup.sh <domain> <tee_target> [allowlist]
#
# Example:
#   sudo ./setup.sh proxy.example.com tee.backend.com:443
#   sudo ./setup.sh proxy.example.com tee.backend.com:443 "tee.backend.com:443,backup.backend.com:443"

set -e

DOMAIN="${1:-}"
TEE_TARGET="${2:-}"
ALLOWLIST="${3:-$TEE_TARGET}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

usage() {
    echo "Usage: sudo $0 <domain> <tee_target> [allowlist]"
    echo ""
    echo "Arguments:"
    echo "  domain      Your domain for the proxy (e.g., proxy.example.com)"
    echo "  tee_target  Default TEE backend host:port (e.g., tee.backend.com:443)"
    echo "  allowlist   Comma-separated allowed targets (default: same as tee_target)"
    echo ""
    echo "Example:"
    echo "  sudo $0 proxy.example.com tee.backend.com:443"
    exit 1
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run as root (use sudo)"
    fi
}

check_args() {
    if [ -z "$DOMAIN" ] || [ -z "$TEE_TARGET" ]; then
        usage
    fi
}

install_dependencies() {
    log "Updating package lists..."
    apt-get update -qq

    log "Installing dependencies..."
    apt-get install -y -qq \
        debian-keyring \
        debian-archive-keyring \
        apt-transport-https \
        curl \
        netcat-openbsd
}

install_caddy() {
    if command -v caddy &> /dev/null; then
        log "Caddy already installed"
        return
    fi

    log "Installing Caddy..."
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
        gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
        tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null

    apt-get update -qq
    apt-get install -y -qq caddy
}

install_rust() {
    if command -v cargo &> /dev/null; then
        log "Rust already installed"
        return
    fi

    log "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
}

build_proxy() {
    if [ -f /usr/local/bin/ratls-proxy ]; then
        warn "ratls-proxy already exists at /usr/local/bin/ratls-proxy"
        read -p "Rebuild? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return
        fi
    fi

    log "Building ratls-proxy..."

    # Check if we're in the repo
    if [ -f "Cargo.toml" ] && grep -q "ratls-proxy" Cargo.toml 2>/dev/null; then
        cargo build -p ratls-proxy --release
        cp target/release/ratls-proxy /usr/local/bin/
    elif [ -f "../../../Cargo.toml" ]; then
        pushd ../../.. > /dev/null
        cargo build -p ratls-proxy --release
        cp target/release/ratls-proxy /usr/local/bin/
        popd > /dev/null
    else
        error "Cannot find ratls-proxy source. Run this script from the repository."
    fi

    chmod +x /usr/local/bin/ratls-proxy
    log "Installed ratls-proxy to /usr/local/bin/"
}

configure_proxy() {
    log "Configuring ratls-proxy..."

    # Create config directory
    mkdir -p /etc/ratls-proxy

    # Write environment file
    cat > /etc/ratls-proxy/env << EOF
RATLS_PROXY_LISTEN=127.0.0.1:9000
RATLS_PROXY_TARGET=$TEE_TARGET
RATLS_PROXY_ALLOWLIST=$ALLOWLIST
EOF

    chmod 600 /etc/ratls-proxy/env
    log "Created /etc/ratls-proxy/env"
}

install_service() {
    log "Installing systemd service..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [ -f "$SCRIPT_DIR/ratls-proxy.service" ]; then
        cp "$SCRIPT_DIR/ratls-proxy.service" /etc/systemd/system/
    else
        cat > /etc/systemd/system/ratls-proxy.service << 'EOF'
[Unit]
Description=RA-TLS WebSocket Proxy
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
EnvironmentFile=/etc/ratls-proxy/env
ExecStart=/usr/local/bin/ratls-proxy
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    fi

    systemctl daemon-reload
    systemctl enable ratls-proxy
    systemctl start ratls-proxy

    log "ratls-proxy service started"
}

configure_caddy() {
    log "Configuring Caddy for domain: $DOMAIN"

    # Create log directory
    mkdir -p /var/log/caddy
    chown caddy:caddy /var/log/caddy

    cat > /etc/caddy/Caddyfile << EOF
$DOMAIN {
    reverse_proxy /tunnel* localhost:9000 {
        transport http {
            keepalive 30s
            keepalive_idle_conns 10
        }
    }
    respond /health "OK" 200
    log {
        output file /var/log/caddy/ratls-proxy.log
        format json
    }
}
EOF

    systemctl reload caddy
    log "Caddy configured and reloaded"
}

verify_setup() {
    log "Verifying setup..."

    echo ""
    echo "Service status:"
    systemctl status ratls-proxy --no-pager -l || true

    echo ""
    echo "Checking if proxy is listening..."
    if nc -z localhost 9000 2>/dev/null; then
        echo -e "${GREEN}ratls-proxy is listening on port 9000${NC}"
    else
        warn "ratls-proxy may not be listening yet"
    fi

    echo ""
    echo "Caddy status:"
    systemctl status caddy --no-pager -l || true
}

print_summary() {
    echo ""
    echo -e "${GREEN}=== Setup Complete ===${NC}"
    echo ""
    echo "Configuration:"
    echo "  Domain: $DOMAIN"
    echo "  TEE Target: $TEE_TARGET"
    echo "  Allowlist: $ALLOWLIST"
    echo ""
    echo "Endpoints:"
    echo "  WebSocket: wss://$DOMAIN/tunnel"
    echo "  Health: https://$DOMAIN/health"
    echo ""
    echo "Commands:"
    echo "  View logs: journalctl -u ratls-proxy -f"
    echo "  Restart: systemctl restart ratls-proxy"
    echo "  Edit config: nano /etc/ratls-proxy/env"
    echo ""
    echo "Test connection:"
    echo "  curl https://$DOMAIN/health"
    echo "  websocat wss://$DOMAIN/tunnel"
}

# Main
check_root
check_args
install_dependencies
install_caddy
install_rust
build_proxy
configure_proxy
install_service
configure_caddy
verify_setup
print_summary
