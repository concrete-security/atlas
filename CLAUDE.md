# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

See @AGENTS.md for the full project overview, workspace layout, architecture, and standards.

## Quick reference

```bash
# Verify changes (run after edits)
make test                                # Native Rust tests (core + proxy)
make test-wasm                           # Check WASM compiles
cargo fmt --all --check                  # Format check
cargo clippy --workspace --exclude atlas-wasm  # Lint

# Single test
cargo test -p atlas-rs <test_name>
cargo test -p atlas-proxy <test_name>

# Full CI match
make test-all && make test-wasm-node
```

## Workflow

- After code changes, run `make test` and `make test-wasm` to catch both native and WASM breakage.
- If unsure about architecture, read @core/ARCHITECTURE.md before editing core modules.
- Native vs WASM split uses `#[cfg(target_arch = "wasm32")]` — keep both variants compiling.

## Debugging

- Core (native): `DEBUG_ATLS=1` for `atlas_rs=debug` logs.
- Node wrapper: `ATLS_DEBUG=1` for JS-side debug output.
- Proxy: requires `ATLS_PROXY_ALLOWLIST` env var (rejects all connections by default).
