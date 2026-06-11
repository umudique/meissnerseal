<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# MeissnerSeal Security Assurance Architecture

**Status:** Architecture reference — v4.0
**Related:** [threat_model.md](threat_model.md),
            [docs/architecture/mvp_roadmap.md](../../docs/architecture/mvp_roadmap.md),
            [docs/security/standards_conformance.md](../../docs/security/standards_conformance.md)

---

## 1. Principle

Security assurance is part of the architecture, not a post-development activity.
Every high-risk security claim maps to:
- A component owner
- A threat or misuse case
- A technical control
- A test or verification method
- A release gate
- An evidence artifact

---

## 2. Security Control Matrix

| Control | Threat | Component | Verification | Phase | Evidence |
|---|---|---|---|---:|---|
| Canonical vault binary format | Parser ambiguity, migration failures | Serialization Layer | Format vectors, fuzzing, round-trip tests | MVP-0 | `vault_format_v1.md`, vectors |
| Secret wrapper types | Accidental logging | `meissnerseal-security`, `meissnerseal-crypto` | Unit tests | MVP-0 | Secret type policy |
| Redacted Debug/Display | Secret in logs/crashes | Core, FFI, UI | Snapshot/logging tests | MVP-0 | Redaction test report |
| Zeroization | Plaintext memory residue | Crypto, FFI | Unit tests, Miri | MVP-0 | Memory hygiene checklist |
| Scoped plaintext API | Long-lived plaintext ownership | Vault Engine, FFI | API tests | MVP-0 | Scoped API policy |
| FFI/Dart lease model | Dart heap plaintext | FFI, Desktop | Integration tests | MVP-1 | Secret view lease tests |
| Clipboard timeout | Clipboard leakage | Desktop/Mobile | UI/platform tests | MVP-1 | Clipboard test results |
| Crash-safe writes | Vault corruption | Vault Engine | Fault-injection tests | MVP-1 | Write strategy test report |
| AEAD with AAD binding | Tampering, wrong-context | Crypto Provider | Test vectors, negative tests | MVP-0 | Crypto vectors |
| Unique nonce + fresh record key | AEAD misuse, nonce reuse | Crypto Provider | Property tests, vectors | MVP-0 | Nonce policy tests |
| Argon2id KDF + TLV encoding | Offline vault theft | Crypto Provider | KDF vectors, TLV round-trip | MVP-0 | `vault_kdf_v1.json` |
| MUK→VKEK→VRK wrapping chain | Key derivation error, wrap/unwrap failure | Key Manager, Crypto Provider | Key hierarchy vectors, wrap/unwrap round-trip | MVP-0 | `vault_kdf_v1.json` |
| HKDF info string encoding | Cross-platform key mismatch, domain confusion | Key Manager | Deterministic info string tests; cross-platform round-trip | MVP-0 | HKDF registry, test vectors |
| HKDF domain separation | Key confusion, cross-context reuse | Key Manager | Info-string registry tests | MVP-0 | HKDF registry |
| Recovery kit encoding | Transcription errors | Recovery Manager | Bech32m tests, vectors | MVP-1 | `recovery_kit_v1.md` |
| Recovery kit theft mitigation | Physical adversary | Recovery Manager, UX | UX warning review, passphrase option tests | MVP-1 | Recovery kit spec |
| Export bundle encryption | `.msexp` theft from disk | CLI, Vault Engine | Export/import vectors, passphrase derivation tests | MVP-0/1 | `.msexp` format spec |
| Transfer transcript binding | MITM, downgrade | Transfer Protocol | Vectors, ProVerif model | MVP-2 | Transfer spec |
| X25519 + ML-KEM hybrid | Harvest-now attack | PQC Provider | Vectors, protocol review | MVP-2 | Hybrid profile doc |
| Relay TTL + payload policy | Relay abuse, metadata overexposure | Relay Service | API tests, rate-limit tests | MVP-2/5 | Relay threat model |
| Replay protection | Network replay | Transfer Protocol | Negative tests | MVP-2 | Replay tests |
| Algorithm ID authentication | Downgrade attacks | Crypto/PQC boundary | Negative tests | MVP-2 | Downgrade test report |
| Device pairing OOB verification | Pairing MITM without OOB check | Device Manager | TOFU label tests, Tamarin model | MVP-2/Beta | Pairing spec |
| Device signing key invariant | Approved device without signing key | Device Manager | Invariant rejection test (trust_state=Approved, signing_key=None) | MVP-2 | Pairing spec |
| Device revocation propagation | Compromised trusted device | Device Manager, Sync | Integration tests, TLA+/Tamarin | MVP-3/Beta | Revocation tests |
| Sync version vectors | Lost concurrent updates | Sync Protocol | TLA+ model, property tests | MVP-3 | Sync conflict model |
| Version-vector pruning | Unbounded vector growth | Sync Protocol | TLA+ compaction model | MVP-3 | Pruning spec |
| Device-signed sync API | Unauthorized sync commits | Sync Server, Device Manager | Canonical request tests | MVP-3 | Sync auth spec |
| Sync envelope encryption | Server compromise | Sync Protocol | Vectors, parser fuzzing | MVP-3 | Sync spec |
| Metadata minimization | Insider admin, server metadata leakage | Sync Server | Contract tests, data inventory | MVP-3 | Metadata inventory |
| Timing side-channel awareness | Local malware, timing oracle | Crypto boundary | Constant-time review checklist; dudect-style tests (Beta) | MVP-0/Beta | Side-channel checklist |
| Browser extension isolation | Malicious extension | Native Host | Extension ID allowlist tests, schema fuzzing | MVP-4 | NM protocol tests |
| Parser fuzzing | Malformed input exploitation | Parsers | cargo-fuzz/AFL++ | MVP-0+ | Fuzz corpus/report |
| CLI shell-history protections | Secret leakage via argv | CLI | Unsafe argv rejection tests | MVP-0 | CLI safety spec |
| Static dependency audit | Supply-chain compromise | CI/Release | cargo-audit/deny | MVP-0 | CI report |
| Signed releases | Release tampering | Release engineering | Signature verification | Beta | Release checklist |
| SBOM | Dependency visibility | Release engineering | SBOM generation | Beta | SBOM file |
| Formal protocol model | Protocol design errors | Security architecture | ProVerif/TLA+/Tamarin by phase | MVP-2/3/Beta | Model files |

---

## 3. Security Claims Matrix

### 3.1 Supported After Implementation

| Claim | Required Evidence |
|---|---|
| Local-first encrypted vault | Vault works offline; vault file encrypted; threat model published |
| Conservative data-at-rest cryptography | Crypto design, primitive registry, test vectors |
| Zero-knowledge encrypted sync | Sync spec, server data inventory, review |
| Hybrid post-quantum-ready transfer | X25519+ML-KEM implementation, transcript tests, protocol spec |
| Crypto-agile vault format | Versioned header, algorithm registry, migration tests |
| Fuzz-tested parsers | Implemented fuzz targets, CI/security-lab reports |
| Public threat model | Maintained threat model document |
| Open security specification | Vault/transfer/sync protocol docs |

### 3.2 Conditional Claims

| Claim | Conditions |
|---|---|
| Hardware-backed key protection | Only where OS secure storage / TPM / Secure Enclave / TrustZone is implemented and enabled |
| Timing side-channel awareness | Only for reviewed cryptographic boundaries; not a global guarantee |
| Self-hostable zero-knowledge sync | Only if deployment follows documented secure configuration |
| Enterprise auditability | Only after audit event model, admin controls, no-secret logging are implemented |
| Formal verification | Only for the exact protocols/modules modeled and published |

### 3.3 Future Claims (Require More Evidence)

| Claim | Required Before Use |
|---|---|
| Independent security audit completed | External audit report or summary |
| Reproducible builds | Build process and verification instructions |
| Side-channel tested boundary | Timing test harnesses and documented scope |
| Enterprise-ready governance | RBAC, admin console, policy engine, audit log review |
| Production-ready seed phrase protection | External review, stable release, recovery model docs |

### 3.4 Explicit Non-Claims

MeissnerSeal must never claim:
- Unhackable security
- Absolute quantum-proof protection
- Resistance to a fully compromised endpoint
- Resistance to all side-channel attacks
- Resistance to power/EM/fault injection in MVP
- Protection from malicious OS or malicious hardware
- That AI review replaces independent human security review
- That hardware-backed storage is equally secure on every platform

---

## 4. Verification and Assurance Pipeline

```
Developer Commit
  -> Formatting and linting
  -> Unit tests
  -> Property-based tests
  -> Static dependency/security analysis (cargo audit, cargo deny)
  -> Parser fuzzing corpus run
  -> Protocol test vectors
  -> Negative security tests
  -> Build reproducibility checks (Beta+)
  -> Signed release/checksum generation (Beta+)
  -> Security review checklist
```

---

## 5. Formal and Mathematical Verification Roadmap

Mathematical verification (Rust-level) — see ADR-015:

| Priority | Tool | Scope | Phase | Artifact |
|---:|---|---|---:|---|
| Required | Const generics | `Key<N>` length invariants at compile time | MVP-0 | type definitions |
| Required | Kani | Length, bounds, no-overflow, no-panic proofs | MVP-0 | `#[cfg(kani)]` harnesses |
| Beta target | Prusti | Hoare triples on key derivation and parsers | Beta | `#[cfg(prusti)]` annotations |
| Research | Creusot / Coq | High-assurance Rust logic, single functions | Research | proof artifacts |

Protocol formal verification (design-level):

| Priority | Tool | Scope | Phase | Artifact |
|---:|---|---|---:|---|
| Required | ProVerif | Transfer protocol secrecy/authentication | MVP-2 | `transfer_protocol.pv` |
| Required | TLA+ | Sync state machine, version vectors, conflict preservation | MVP-3 | `sync_state_machine.tla` |
| Beta target | Tamarin | Device pairing, replay, downgrade, revocation | Beta | `device_pairing.spthy` |

---

## 6. Release Security Gates

| Gate | Alpha | Beta | Production | Enterprise |
|---|:---:|:---:|:---:|:---:|
| Unit tests | ✓ | ✓ | ✓ | ✓ |
| Property tests | ✓ | ✓ | ✓ | ✓ |
| Parser fuzzing | Initial | ✓ | ✓ | ✓ |
| cargo audit / deny | ✓ | ✓ | ✓ | ✓ |
| Threat model | Draft | Published | Maintained | Maintained |
| Crypto design doc | Draft | Published | Maintained | Reviewed |
| Protocol spec | Transfer draft | Transfer + sync | Reviewed | Reviewed |
| Signed releases | Planned | ✓ | ✓ | ✓ |
| SBOM | Optional | ✓ | ✓ | ✓ |
| Reproducible builds | Target | Target | Where practical | Where practical |
| External review | Planned | Protocol review | Focused audit | Audit + pentest |
| Responsible disclosure | ✓ | ✓ | ✓ | ✓ |

---

## 7. Side-Channel Protection Hierarchy

Side-channel protection is organized in three layers. See ADR-014 for the
full rationale. Noise-based approaches (Layer 3) do not provide mathematical
guarantees — statistical averaging removes noise given enough measurements.

### Layer 1 — Primary (mandatory for meissnerseal-crypto and meissnerseal-pqc)

- Constant-time implementation using `subtle` crate
- No secret-dependent branches or memory accesses
- Verification: Miri (UB detection, every change), dudect (timing leakage, Beta)
- BINSEC/checkct binary-level verification (Beta)

### Layer 2 — Secondary (where applicable)

- Algorithmic masking: randomize inputs before cryptographic operations
- Point blinding for ECC operations
- Provides defense even against attackers with many measurements

### Layer 3 — Tertiary (defense-in-depth, documented limitations)

- Noise and dummy operations may supplement Layers 1 and 2
- Limitations must be documented: statistical averaging removes noise over N measurements
- Must not interfere with Layer 1 constant-time properties
- Must not be described as a security guarantee in product communications

### Out of Scope (MVP)

- Power analysis (SPA/DPA)
- Electromagnetic leakage
- Fault injection
- Speculative execution attacks (Spectre/Meltdown)
- Cache side-channel across hostile co-tenant workloads
- Hardware implant resistance
