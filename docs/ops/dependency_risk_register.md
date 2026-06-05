# Arcanum Dependency Risk Register

**Update policy:** Review cryptographic dependencies on every version bump.
Review all dependencies monthly during active development.

---

## Cryptographic Dependencies (Critical)

| Crate | Purpose | Risk Level | Last Reviewed | Notes |
|---|---|---|---|---|
| `argon2` | Argon2id KDF | Critical | — | Pure Rust, RustCrypto maintained |
| `chacha20poly1305` | XChaCha20-Poly1305 AEAD | Critical | — | Pure Rust, RustCrypto maintained |
| `aes-gcm` | AES-256-GCM AEAD (strict optional) | Critical | — | RustCrypto; constant-time claims documented |
| `hkdf` | HKDF-SHA256/SHA384 | Critical | — | RustCrypto |
| `sha2` | SHA-256/384 | Critical | — | RustCrypto |
| `rand` | OS CSPRNG wrapper | Critical | — | Must use `getrandom` feature |
| `zeroize` | Secret buffer zeroization | Critical | — | RustCrypto ecosystem |
| `subtle` | Constant-time operations | Critical | — | dalek-cryptography |
| `bech32` | Recovery secret encoding | Medium | — | Review encoding correctness |

## PQC Dependencies (Critical — to be selected)

| Crate | Purpose | Risk Level | Notes |
|---|---|---|---|
| TBD (ML-KEM) | ML-KEM-768 key encapsulation | Critical | Evaluate: pqcrypto, liboqs Rust bindings, or native impl |

**PQC selection criteria:**
- Must have constant-time implementation claims or evidence
- Must be based on final NIST FIPS 203 specification
- Prefer pure Rust or well-audited C with narrow FFI
- Review side-channel claims before selection

## FFI and Serialization Dependencies (High)

| Crate | Purpose | Risk Level | Notes |
|---|---|---|---|
| `uuid` | UUID v4 generation | Low | — |
| `serde` + `serde_json` | Serialization | Medium | Confined to non-secret metadata |
| `clap` | CLI argument parsing | Low | No secret values through CLI args |

## Rules

- Pin cryptographic dependency minor versions in `Cargo.lock`
- Review cryptographic dependency updates manually before accepting
- `cargo audit` runs in CI on every commit
- `cargo deny` enforces license and banned crate policy
- New cryptographic dependencies require team review before merge
