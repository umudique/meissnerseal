# ADR-011: RustCrypto Ecosystem as Primary Cryptographic Dependency

**Date:** 2025-06
**Status:** Accepted

## Context

Arcanum requires implementations of Argon2id, XChaCha20-Poly1305, AES-256-GCM,
HKDF-SHA256, SHA-256, and OS CSPRNG. A dependency ecosystem must be chosen.

## Alternatives Considered

1. **libsodium via sodiumoxide / libsodium-sys**
   - Well-audited C library, widely used
   - C FFI introduces memory safety boundary concerns
   - Limited crypto-agility for our profile-based design
   - Rejected: FFI boundary risk outweighs audit benefit for this project

2. **ring (by briansmith)**
   - Excellent audit history, used in production at scale
   - Opinionated API, limited algorithm flexibility
   - No Argon2 support; no XChaCha20 in stable API
   - Rejected: does not cover the full primitive set

3. **RustCrypto ecosystem (rust-lang/RustCrypto)**
   - Pure Rust implementations, no C FFI for symmetric primitives
   - Covers the complete Arcanum primitive set
   - Consistent API design across crates
   - Active maintenance with security disclosure process
   - Used by a large portion of the Rust security ecosystem

## Decision

Use RustCrypto ecosystem as primary cryptographic dependency:
- `argon2` — KDF_ARGON2ID_V1
- `chacha20poly1305` — AEAD_XCHACHA20_POLY1305_V1
- `aes-gcm` — AEAD_AES_256_GCM_STRICT_V1
- `hkdf` — HKDF-SHA256
- `sha2` — SHA-256/384
- `rand` (with `getrandom` feature) — OS CSPRNG wrapper
- `zeroize` — secret buffer zeroization
- `subtle` — constant-time operations
- `bech32` — recovery secret encoding

## Audit Status Per Crate

| Crate | Audit Status | Notes |
|---|---|---|
| `zeroize` | Audited (iqlusion, 2020) | Stable, widely reviewed |
| `subtle` | Reviewed (dalek-cryptography) | Constant-time library |
| `sha2` | Reviewed | RustCrypto core, high scrutiny |
| `hkdf` | Reviewed | Straightforward RFC 5869 impl |
| `chacha20poly1305` | Reviewed | RustCrypto, test-vector verified |
| `aes-gcm` | Reviewed | RustCrypto, AES-NI backend available |
| `argon2` | Reviewed | PHC reference impl in Rust |
| `rand` / `getrandom` | Reviewed | Widely used, OS CSPRNG delegation |
| `bech32` | Reviewed | Bitcoin BIP-173/350 reference impl |

## Consequences

- All cryptographic crates are pure Rust — no C FFI boundary for symmetric operations
- Miri can test cryptographic code without FFI limitations
- ML-KEM crate selection is a separate decision (ADR-012)
- Cryptographic dependency updates require manual review before acceptance
- `cargo audit` and `cargo deny` run on every commit to detect CVEs
