# atlas-python

Attested TLS (aTLS) for Python. Connect securely to Trusted Execution Environments (TEEs) with httpx.

> **For aTLS protocol details, policy configuration, and security features, see [core/README.md](../core/README.md)**

## Installation

```bash
pip install atlas-python
```

Prebuilt wheels are available for:
- Linux (x64, arm64)
- macOS (x64, arm64)
- Windows (x64)

## Quick Start

```python
from atlas import httpx
from atlas.policy import dstack_tdx_policy

policy = dstack_tdx_policy(
    app_compose_docker_compose_file="...",
    expected_bootchain={
        "mrtd": "b24d3b24...",
        "rtmr0": "24c15e08...",
        "rtmr1": "6e1afb74...",
        "rtmr2": "89e73ced...",
    },
    os_image_hash="86b18137...",
)

with httpx.Client(
    atls_policy_per_hostname={"enclave.example.com": policy}
) as client:
    response = client.get("https://enclave.example.com/api/data")
    print(response.status_code)
    print(response.extensions.get("attestation"))
    # {"trusted": True, "tee_type": "tdx", "tcb_status": "UpToDate", ...}
```

## Development Policy

For testing without bootchain verification:

```python
from atlas import httpx
from atlas.policy import dev_policy

with httpx.Client(
    atls_policy_per_hostname={"enclave.example.com": dev_policy()}
) as client:
    response = client.get("https://enclave.example.com/health")
```

> **Warning**: `dev_policy()` disables runtime verification. Do not use in production.

## API

### `atlas.httpx.Client`

An `httpx.Client` subclass with aTLS support. Connections to hostnames in `atls_policy_per_hostname` go through Rust aTLS (TLS + EKM binding + attestation). Other hostnames use standard HTTPS.

```python
from atlas.httpx import Client

client = Client(atls_policy_per_hostname={"host.com": policy})
```

### `atlas.policy.dstack_tdx_policy(**kwargs)`

Build a DStack TDX attestation policy dict

| Parameter | Type | Description |
|---|---|---|
| `app_compose` | `dict \| None` | Base app compose config |
| `expected_bootchain` | `dict \| None` | `{"mrtd": ..., "rtmr0": ..., "rtmr1": ..., "rtmr2": ...}` |
| `os_image_hash` | `str \| None` | SHA256 hex of OS image |
| `allowed_tcb_status` | `list[str]` | Default: `["UpToDate"]` |
| `disable_runtime_verification` | `bool` | Skip runtime checks (dev only) |
| `app_compose_docker_compose_file` | `str \| None` | Override `docker_compose_file` in app_compose |
| `app_compose_allowed_envs` | `list[str] \| None` | Override `allowed_envs` in app_compose |
| `pccs_url` | `str \| None` | Intel PCCS URL for collateral |
| `cache_collateral` | `bool` | Cache Intel collateral between verifications |

### `atlas.policy.dev_policy()`

Returns a relaxed policy for development/testing.

### `atlas.policy.merge_with_default_app_compose(user_compose)`

Merge user-provided app_compose fields with default values.

## Policy Configuration

Policies are JSON-serializable dicts that map to the Rust core's `Policy` enum. For complete policy field descriptions, verification flow, and computing bootchain measurements, see:

- [core/README.md#policy-configuration](../core/README.md#policy-configuration)
- [core/BOOTCHAIN-VERIFICATION.md](../core/BOOTCHAIN-VERIFICATION.md)

## How It Works

Python bindings use the Rust core via PyO3 for the full aTLS pipeline:

1. **TCP Connection** - Python requests connection to a TEE endpoint
2. **TLS Handshake** - Rust establishes TLS 1.3 with EKM session binding
3. **Attestation** - Rust fetches and verifies the TDX quote against the policy
4. **Stream Return** - The attested TLS stream is returned to Python
5. **HTTP** - httpx sends requests over the attested stream

All TLS and verification happens in Rust. Python handles HTTP protocol and provides the httpx/API wrapper.

## Building from Source

Requires Rust stable and Python 3.10+:

```bash
cd python

# Install dependencies
uv sync --group dev --group test

# Build and install in development mode
uv run maturin develop

# Run tests
make test

# Run linting
make qa-all
```
