<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# MeissnerSeal Dependency Risk Register

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

## PQC Dependencies (Critical)

| Crate | Purpose | Risk Level | Audit Status | Decision |
|---|---|---|---|---|
| `ml-kem` (RustCrypto) | ML-KEM-768 key encapsulation | Critical | No independent audit (2026-06); FIPS 203 compliant; constant-time via `subtle`; wide deployment; no known advisories | Selected 2026-06-16 — ADR-034; version pinned in `Cargo.lock` at integration time |
| `ml-dsa` (RustCrypto) | ML-DSA-87 digital signatures (hybrid) | Critical | No independent audit (2026-07); FIPS 204 compliant; RustCrypto ecosystem; no known advisories | Integrated 2026-07-23 — ADR-028 amendment; same risk framework as `ml-kem` (ADR-034) |

**ML-KEM risk notes:** No independent security audit as of 2026-06. The two High residual risks
from ADR-012 (audit gap, side-channel) remain at their original values — ADR-034 explicitly does
not upgrade them. Mitigations: hybrid design (X25519 + ML-KEM, ADR-035) means classical security
holds independently; Kani harnesses required at the `meissnerseal-pqc` API boundary (PQC-1).
See [ADR-034](../adr/ADR-034-rustcrypto-mlkem-backend.md) for full rationale.

**ML-DSA risk notes:** No independent security audit as of 2026-07. The audit-maturity gate
from the original ADR-028 was removed on 2026-07-23 — it was inconsistent with how `ml-kem`
was accepted under ADR-034 (same absence of independent audit, same hybrid reasoning).
`libcrux-ml-dsa` (formally-verified alternative) remains excluded — RUSTSEC-2026-0077,
RUSTSEC-2026-0126, and silent-disclosure behavior (ADR-034 §2–3). Mitigations: hybrid design
(Ed25519 + ML-DSA-87, ADR-028 amendment) means Ed25519 validity is independent of ML-DSA
correctness — both components must hold (AND combiner); Kani harnesses required at the
`meissnerseal-pqc` API boundary (PQC-4). See [ADR-028](../adr/ADR-028-signature-crypto-agility.md)
for full rationale.

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
