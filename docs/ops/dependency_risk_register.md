<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Arcanum Dependency Risk Register

**Update policy:** Review cryptographic dependencies on every version bump.
Review all dependencies monthly during active development.

---

## Cryptographic Dependencies (Critical)

| Crate | Purpose | Risk Level | Trust Tier | Last Reviewed | Notes |
|---|---|---|---|---|---|
| `zeroize` | Secret buffer zeroization | Critical | T1 — Audited | — | Audited by iqlusion (2020) |
| `subtle` | Constant-time operations | Critical | T2 — Reviewed | — | dalek-cryptography; constant-time claims documented |
| `sha2` | SHA-256/384 | Critical | T2 — Reviewed | — | RustCrypto core; test-vector verified |
| `hkdf` | HKDF-SHA256/SHA384 | Critical | T2 — Reviewed | — | RFC 5869 compliance; RustCrypto |
| `chacha20poly1305` | XChaCha20-Poly1305 AEAD | Critical | T2 — Reviewed | — | RustCrypto; test-vector verified |
| `aes-gcm` | AES-256-GCM (strict optional) | Critical | T2 — Reviewed | — | RustCrypto; AES-NI backend; constant-time claims |
| `argon2` | Argon2id KDF | Critical | T2 — Reviewed | — | PHC reference impl in Rust |
| `rand` + `getrandom` | OS CSPRNG wrapper | Critical | T2 — Reviewed | — | Delegates to OS kernel entropy; getrandom feature required |
| `bech32` | Recovery secret encoding | Medium | T3 — Evaluated | — | BIP-173/350; no formal security audit |

---

## PQC Dependencies (Critical — Selection Pending)

| Crate | Purpose | Risk Level | Audit Status | Decision |
|---|---|---|---|---|
| TBD | ML-KEM-768 key encapsulation | Critical | **No independent audit (2025-06)** | Pending — see ADR-012 |

### ML-KEM Crate Selection

**Status:** Not yet selected. Must be selected and documented before MVP-2.

**Risk summary:** See [ADR-012](../adr/ADR-012-mlkem-risk.md) for full analysis.
Key points:
- NIST FIPS 203 standard is finalized — specification risk is low
- RustCrypto `ml-kem` crate has no independent security audit as of 2025-06
- Hybrid design (X25519 + ML-KEM) means classical security holds even if ML-KEM fails
- Version must be pinned in Cargo.lock; version bumps require manual review

**Selection criteria (must satisfy all):**
- Based on final NIST FIPS 203, not draft versions
- Constant-time implementation with documented evidence or claims
- Pure Rust preferred; C FFI acceptable only with narrow, well-audited binding
- Active maintenance with a security disclosure process
- Passes `cargo audit` with no known advisories at time of selection

**Candidates to evaluate before MVP-2:**

| Candidate | Ecosystem | CT Claims | Audit | Notes |
|---|---|---|---|---|
| `ml-kem` (RustCrypto) | RustCrypto | Documented | None (2025-06) | Most likely choice; consistent with ADR-011 |
| `pqcrypto-kyber` | pqcrypto | C FFI (liboqs) | Partial | C dependency; liboqs is more mature |
| `oqs` (liboqs Rust) | Open Quantum Safe | C FFI | NIST process review | Broader scope; larger FFI surface |

**Update this row when a crate is selected:**
```
| <crate> | ML-KEM-768 | Critical | <audit status> | Selected <date>; version <x.y.z> pinned |
```

---

## FFI and Serialization Dependencies

| Crate | Purpose | Risk Level | Trust Tier | Notes |
|---|---|---|---|---|
| `uuid` | UUID v4 generation | Low | T3 | — |
| `serde` + `serde_json` | Serialization | Medium | T3 | Confined to non-secret metadata only |
| `clap` | CLI argument parsing | Low | T3 | No secret values through argv |
| `anyhow` | Error handling (CLI/server) | Low | T3 | — |
| `thiserror` | Error type derivation | Low | T3 | — |
| `tokio` | Async runtime (sync server only) | Medium | T3 | Large transitive surface; isolated to sync-server |

---

## Trust Tier Definitions

| Tier | Definition |
|---|---|
| T1 — Audited | Independent security audit completed and published |
| T2 — Reviewed | Extensive community review, test-vector verified, widely deployed |
| T3 — Evaluated | Used in production, no known issues, community-maintained |
| T4 — Pending | Newer crate, lower audit history, requires active tracking |

---

## Rules

- Pin cryptographic dependency minor versions in `Cargo.lock`
- Review cryptographic dependency updates manually before accepting
- `cargo audit` runs in CI on every commit
- `cargo deny` enforces license and banned crate policy
- New cryptographic dependencies require human review before merge
- Agent cannot change dependency versions without human approval (AGENTS.md §6)
- ML-KEM crate must be selected and this register updated before MVP-2
