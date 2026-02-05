# Bootchain Verification for DstackTDXVerifier

This document explains how bootchain verification works in the `DstackTDXVerifier` implementation and how to compute measurements for different Dstack versions.

## Overview

Bootchain verification ensures the TEE (Trusted Execution Environment) has booted with a known, trusted chain of components from firmware through kernel. This verification establishes trust in the entire boot process before the application layer.

### What Gets Verified

The verification covers the full boot process through TDX measurement registers:

| Register | Purpose | What It Measures | Scope |
|----------|---------|------------------|-------|
| **MRTD** | Initial TD Measurement | TD memory contents and configuration (TDVF/firmware) | General TDX |
| **RTMR0** | Hardware Environment | Virtual hardware environment the TD operates within | General TDX |
| **RTMR1** | Kernel | Linux kernel loaded during boot | General TDX |
| **RTMR2** | Kernel Config | Kernel command-line parameters and initramfs (initrd) | General TDX |
| **RTMR3** | Application | App compose, TLS certificates, and other runtime measurements | Dstack-specific |

> **Note:** MRTD and RTMR0-2 verification is generic for Intel TDX measurements. However, RTMR3 verification is Dstack-specific: it relies on Dstack's event log format containing app compose hashes, TLS certificate bindings, and OS image hashes. Other TDX runtimes may use RTMR3 differently or not at all.

### Verification Flow in DstackTDXVerifier

The complete verification flow is:

1. **TLS Certificate Verification** - Certificate hash in event log matches the connection
2. **DCAP Quote Verification** - Quote signature is valid and TCB status is acceptable
3. **Bootchain Verification** - MRTD and RTMR0-2 match expected values
4. **RTMR Replay Verification** - Event log correctly produces all RTMRs
5. **App Compose Verification** - Application configuration matches expected
6. **OS Image Hash Verification** - OS image hash in event log matches expected

## How to Use

### Why You Must Compute Your Own Measurements

Bootchain measurements (MRTD, RTMR0-2) depend on hardware configuration, not just the Dstack version. The same Dstack version running on different machines will produce different measurements due to:

- **CPU count** - Number of vCPUs allocated to the VM
- **Memory size** - Amount of RAM allocated
- **PCI hole size** - PCI memory address space configuration
- **Number of GPUs** - GPU passthrough configuration
- **Number of NVSwitches** - NVLink configuration
- **Hotplug configuration** - Whether hotplug is enabled/disabled
- **QEMU version** - The QEMU version used to run the VM

This means there's no single set of "correct" measurements for a Dstack version - you must compute measurements for your specific deployment configuration.

### Providing Bootchain Measurements

You must provide both `expected_bootchain` and `os_image_hash` when runtime verification is enabled:

```rust
use atlas_rs::{DstackTdxPolicy, ExpectedBootchain, Policy};

let policy = Policy::DstackTdx(DstackTdxPolicy {
    expected_bootchain: Some(ExpectedBootchain {
        mrtd: "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077".into(),
        rtmr0: "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96".into(),
        rtmr1: "6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7".into(),
        rtmr2: "89e73cedf48f976ffebe8ac1129790ff59a0f52d54d969cb73455b1a79793f1dc16edc3b1fccc0fd65ea5905774bbd57".into(),
    }),
    os_image_hash: Some("86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a".into()),
    app_compose: Some(serde_json::json!({
        "runner": "docker-compose",
        "docker_compose_file": "..."
    })),
    ..Default::default()
});
```

See the [Computing Measurements](#computing-measurements-for-new-dstack-versions) section below for detailed instructions on how to compute these values for your deployment.

### Security Considerations

- **All runtime fields are required by default**: `expected_bootchain`, `app_compose`, and `os_image_hash` must all be provided
- Missing any of these fields will cause a configuration error
- To skip runtime verification, you must explicitly set `disable_runtime_verification: true` in the policy
- **`DstackTdxPolicy::dev()`** sets `disable_runtime_verification: true` for development convenience
- Disabling runtime verification is **NOT recommended** for production use

## Computing Measurements for New Dstack Versions

This section describes how to compute all measurements (bootchain + OS image hash) for a Dstack version using reproducible builds.

### Requirements

A Linux machine with Docker and Cargo installed.

### Complete Process

The following steps show how to compute all required measurements for a Dstack version (we use [Dstack v0.5.4.1 Nvidia](https://github.com/nearai/private-ml-sdk/releases/tag/v0.5.4.1) as an example).

GPU releases are available at https://github.com/nearai/private-ml-sdk/releases and CPU releases at https://github.com/Dstack-TEE/meta-dstack/releases.

#### 1. Set up working directory

```bash
tmp_wd=$(mktemp -d)
cd $tmp_wd
```

#### 2. Clone dstack and build measurement tools

```bash
# Clone dstack
git clone https://github.com/Dstack-TEE/dstack.git

# Build dstack-mr
cd dstack/dstack-mr/cli/
cargo build --release

# Build dependencies (dstack-acpi-tables and QEMU files)
cd $tmp_wd/dstack
docker build --target acpi-builder -t dstack-acpi-builder -f verifier/builder/Dockerfile verifier/

# Get dependencies from the container
docker container create --name temp-copy dstack-acpi-builder
docker cp temp-copy:/usr/local/bin/dstack-acpi-tables $tmp_wd/dstack-acpi-tables
docker cp temp-copy:/usr/local/share/qemu/. $tmp_wd/.
docker rm temp-copy
```

#### 3. Reproduce and extract the Dstack release

```bash
cd $tmp_wd

# Download the reproduce script
wget https://github.com/nearai/private-ml-sdk/releases/download/v0.5.4.1/reproduce.sh

# Review the script content to verify it builds from expected commit
cat reproduce.sh

# Run the reproducible build
chmod +x reproduce.sh
./reproduce.sh

# Extract the release
tar -xzvf dstack-nvidia-0.5.4.1.tar.gz --strip-components=1
```

#### 4. Compute bootchain measurements (MRTD, RTMR0-2)

Target VM Config example:

```json
{
  "spec_version": 1,
  "os_image_hash": "86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a",
  "cpu_count": 24,
  "memory_size": 274877906944,
  "qemu_version": "9.2.1",
  "pci_hole64_size": 1125899906842624,
  "hugepages": false,
  "num_gpus": 1,
  "num_nvswitches": 0,
  "hotplug_off": true,
  "image": "dstack-nvidia-0.5.4.1"
}
```

Use these values to compute measurements:

```bash
PATH=$tmp_wd/dstack/target/release:$tmp_wd:$PATH dstack-mr measure \
  --num-gpus 1 \
  --cpu 24 \
  --memory 274877906944 \
  --num-nvswitches 0 \
  --hotplug-off true \
  --pci-hole64-size 1125899906842624 \
  --qemu-version "9.2.1" \
  metadata.json
```

Output:
```
Machine measurements:
MRTD: b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217
RTMR0: 24c15e08c07aa01c531cbd7e8ba28f8cb62e78f6171bf6a8e0800714a65dd5efd3a06bf0cf5433c02bbfac839434b418
RTMR1: 6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7
RTMR2: 89e73cedf48f976ffebe8ac1129790ff59a0f52d54d969cb73455b1a79793f1dc16edc3b1fccc0fd65ea5905774bbd57
```

#### 5. Compute OS image hash

The OS image hash is the SHA256 of the `sha256sum.txt` file:

```bash
# View the sha256sum.txt contents (individual component hashes)
cat sha256sum.txt
# 76888ce69c91aed86c43f840b913899b40b981964b7ce6018667f91ad06301f0  ovmf.fd
# e6fa48d3d894331e7b750484ee617f5f00b5695be8326f2a3ff906ef275abe8c  bzImage
# 4b935cdd58b22697cb5a1b789b59f6ef2337dd4e9f5acb1f29bf9ef4c5a05d4a  initramfs.cpio.gz
# 67ebcdef2e771dafc0d3a3f694dfb5e66563723d908b90705434cc898a81be96  metadata.json

# Compute the OS image hash
sha256sum sha256sum.txt
# 86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a  sha256sum.txt
```

#### 6. Clean up

```bash
rm -rf $tmp_wd
```

### Reproducibility

All measurements are computed using Dstack's reproducible builds:
- Building the same Dstack version on different machines produces the same measurements
- This allows independent verification of the Dstack image integrity
- Build process follows: https://github.com/Dstack-TEE/meta-dstack?tab=readme-ov-file#reproducible-build-the-guest-image

## Troubleshooting

### Bootchain Mismatch

If you get a `BootchainMismatch` error:
- Verify you're using the correct Dstack version
- Check that the remote TEE is running the expected Dstack version
- Ensure measurements were computed correctly using `dstack-mr`
- Verify the hardware configuration matches (CPU count, memory, GPUs, etc.)

### OS Image Hash Mismatch

If you get an `OsImageHashMismatch` error:
- The hash is recorded in the event log during boot
- Verify the TEE booted with the expected Dstack image
- Check that the hash was computed correctly from `sha256sum.txt`

## References

- [Dstack GitHub Repository](https://github.com/Dstack-TEE/dstack)
- [Meta-Dstack Reproducible Build](https://github.com/Dstack-TEE/meta-dstack?tab=readme-ov-file#reproducible-build-the-guest-image)
- [Understanding TDX Attestation Reports](https://phala.com/posts/understanding-tdx-attestation-reports-a-developers-guide)
