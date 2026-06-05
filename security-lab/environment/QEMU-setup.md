# QEMU Lab Environment Setup

**Status:** Skeleton — fill before first lab activation (MVP-2)

## Required Tools

- QEMU (x86_64)
- GDB with gdb-dashboard or pwndbg
- Rust toolchain (matching project rust-toolchain.toml)
- cargo-build with debug symbols enabled

## VM Configuration

[Document VM specs, OS image, network isolation settings]

## Build Configuration for Lab

```bash
# Debug build with symbols — never use release binary in memory analysis
cargo build --workspace --profile dev
```

## Isolation Requirements

- VM must have no network access to production systems
- VM must use only synthetic test data — no real vault files
- VM snapshots before each scenario for clean state
