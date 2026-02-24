.PHONY: help test test-all test-wasm test-wasm-node test-proxy build build-wasm build-node build-private-ai-sdk test-node test-private-ai-sdk clean demo-wasm setup-wasm

CARGO ?= cargo
DEMO_PORT ?= 8080

help:
	@echo "Available targets:"
	@echo "  make test           # run native Rust tests (core, proxy)"
	@echo "  make test-proxy     # run proxy unit and integration tests"
	@echo "  make test-wasm      # cargo check atlas-wasm for wasm32 target"
	@echo "  make test-wasm-node # run WASM tests in Node.js via wasm-pack"
	@echo "  make test-node      # run Node.js binding tests"
	@echo "  make test-private-ai-sdk # run AI provider package tests"
	@echo "  make test-all       # run all tests (native + wasm + node + private-ai-sdk)"
	@echo ""
	@echo "  make build          # build all native crates"
	@echo "  make build-wasm     # build WASM package with wasm-pack"
	@echo "  make build-node     # build Node.js native bindings"
	@echo "  make build-private-ai-sdk # build AI provider package"
	@echo "  make setup-wasm     # setup WASM toolchain (macOS only)"
	@echo ""
	@echo "  make demo-wasm      # run proxy + serve demo at http://localhost:$(DEMO_PORT)/demo/"
	@echo ""
	@echo "  make clean          # clean all build artifacts"

# Native Rust tests (excludes WASM crate which needs special toolchain)
test:
	$(CARGO) test --workspace --exclude atlas-wasm

# Proxy unit and integration tests
test-proxy:
	$(CARGO) test -p atlas-proxy

# Check WASM crate compiles for wasm32 target
test-wasm:
	$(CARGO) check -p atlas-wasm --target wasm32-unknown-unknown

# Run WASM tests in Node.js via wasm-pack
test-wasm-node:
	wasm-pack test --node wasm

# Node.js binding tests
test-node:
	cd node && pnpm test

# AI provider package tests
test-private-ai-sdk:
	cd examples/private-ai-sdk && pnpm test

# All tests
test-all: test test-wasm test-node test-private-ai-sdk

# Build all native crates
build:
	$(CARGO) build --workspace --exclude atlas-wasm

# Setup WASM toolchain (macOS only - installs LLVM with wasm32 support)
setup-wasm:
	@if [ "$$(uname)" = "Darwin" ]; then \
		echo "Installing LLVM with WASM support via Homebrew..."; \
		brew install llvm; \
		echo ""; \
		echo "Done! Now run: make build-wasm"; \
	else \
		echo "Linux detected - no additional setup needed"; \
	fi

# Build WASM package (auto-detects macOS LLVM)
build-wasm:
	@command -v wasm-pack >/dev/null || { echo "Error: wasm-pack not found. Install via 'cargo install wasm-pack'"; exit 1; }
	@if [ "$$(uname)" = "Darwin" ] && [ -d "$$(brew --prefix llvm 2>/dev/null)" ]; then \
		export CC="$$(brew --prefix llvm)/bin/clang"; \
		export AR="$$(brew --prefix llvm)/bin/llvm-ar"; \
	fi; \
	cd wasm && wasm-pack build --target web --out-dir pkg
	@cp -f wasm/src/atls-fetch.js wasm/pkg/ 2>/dev/null || true
	@cp -f wasm/src/atls-fetch.d.ts wasm/pkg/ 2>/dev/null || true

# Build Node.js bindings
build-node:
	cd node && pnpm build

# Build AI provider package
build-private-ai-sdk:
	cd examples/private-ai-sdk && pnpm build

# Clean all artifacts
clean:
	$(CARGO) clean
	rm -rf wasm/pkg
	rm -rf node/*.node node/index.cjs

# Serve WASM demo with proxy
PROXY_PORT ?= 9000
PROXY_TARGET ?= vllm.concrete-security.com:443
PROXY_ALLOWLIST ?= $(PROXY_TARGET),google.com:443

demo-wasm:
	@echo "Starting aTLS WASM demo..."
	@echo "  Proxy:  ws://127.0.0.1:$(PROXY_PORT)"
	@echo "  Demos:"
	@echo "    - http://localhost:$(DEMO_PORT)/demo/minimal.html  (basic test)"
	@echo "    - http://localhost:$(DEMO_PORT)/demo/ai-sdk.html   (AI SDK streaming)"
	@echo ""
	@echo "Press Ctrl+C to stop both servers"
	@echo ""
	@trap 'kill 0' EXIT; \
	ATLS_PROXY_TARGET="$(PROXY_TARGET)" ATLS_PROXY_ALLOWLIST="$(PROXY_ALLOWLIST)" ATLS_PROXY_LISTEN="127.0.0.1:$(PROXY_PORT)" \
		$(CARGO) run -p atlas-proxy & \
	sleep 1 && cd wasm && python3 -m http.server $(DEMO_PORT) & \
	wait
