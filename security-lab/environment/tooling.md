# Security Lab Tooling

**Status:** Skeleton — verify versions before lab activation

## Required

| Tool | Purpose | Min Version |
|---|---|---|
| QEMU | Virtualized lab environment | 8.0+ |
| GDB | Runtime memory and execution analysis | 13.0+ |
| Valgrind | Memory error detection | 3.21+ |
| cargo-fuzz | Fuzzing harness | latest stable |
| dudect | Timing side-channel analysis | [TBD] |
| Python 3 | Cross-verification scripts | 3.10+ |
| SageMath | Cryptographic cross-verification | 9.0+ |

## Optional (Beta+)

| Tool | Purpose |
|---|---|
| BINSEC/checkct | Binary-level constant-time verification |
| AFL++ | Alternative fuzzer |
| Kani | Rust bounded model checking |
