# Arcanum Security Assurance Architecture

**Status:** Architecture reference — v4.0
**Related:** [threat_model.md](threat_model.md), [docs/architecture/mvp_roadmap.md](../../docs/architecture/mvp_roadmap.md)

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
| Secret wrapper types | Accidental logging | `arcanum-security`, `arcanum-crypto` | Unit tests | MVP-0 | Secret type policy |
| Redacted Debug/Display | Secret in logs/crashes | Core, FFI, UI | Snapshot/logging tests | MVP-0 | Redaction test report |
| Zeroization | Plaintext memory residue | Crypto, FFI | Unit tests, Miri | MVP-0 | Memory hygiene checklist |
| Scoped plaintext API | Long-lived plaintext ownership | Vault Engine, FFI | API tests | MVP-0 | Scoped API policy |
| FFI/Dart lease model | Dart heap plaintext | FFI, Desktop | Integration tests | MVP-1 | Secret view lease tests |
| Clipboard timeout | Clipboard leakage | Desktop/Mobile | UI/platform tests | MVP-1 | Clipboard test results |
| Crash-safe writes | Vault corruption | Vault Engine | Fault-injection tests | MVP-1 | Write strategy test report |
| AEAD with AAD binding | Tampering, wrong-context | Crypto Provider | Test vectors, negative tests | MVP-0 | Crypto vectors |
| Unique nonce + fresh record key | AEAD misuse, nonce reuse | Crypto Provider | Property tests, vectors | MVP-0 | Nonce policy tests |
| Argon2id KDF + TLV encoding | Offline vault theft | Crypto Provider | KDF vectors, TLV round-trip | MVP-0 | `vault_kdf_v1.json` |
| HKDF domain separation | Key confusion | Key Manager | Info-string registry tests | MVP-0 | HKDF registry |
| Recovery kit encoding | Transcription errors | Recovery Manager | Bech32m tests, vectors | MVP-1 | `recovery_kit_v1.md` |
| Transfer transcript binding | MITM, downgrade | Transfer Protocol | Vectors, ProVerif model | MVP-2 | Transfer spec |
| X25519 + ML-KEM hybrid | Harvest-now attack | PQC Provider | Vectors, protocol review | MVP-2 | Hybrid profile doc |
| Relay TTL + payload policy | Relay abuse | Relay Service | API tests, rate-limit tests | MVP-2/5 | Relay threat model |
| Replay protection | Network replay | Transfer Protocol | Negative tests | MVP-2 | Replay tests |
| Algorithm ID authentication | Downgrade attacks | Crypto/PQC boundary | Negative tests | MVP-2 | Downgrade test report |
| Device pairing verification | MITM during enrollment | Device Manager | Pairing transcript tests | MVP-2/Beta | Pairing spec |
| Device revocation propagation | Continued revoked access | Device Manager, Sync | Integration tests | MVP-3/Beta | Revocation tests |
| Sync version vectors | Lost concurrent updates | Sync Protocol | TLA+ model, property tests | MVP-3 | Sync conflict model |
| Version-vector pruning | Unbounded vector growth | Sync Protocol | TLA+ compaction model | MVP-3 | Pruning spec |
| Device-signed sync API | Unauthorized commits | Sync Server, Device Manager | Canonical request tests | MVP-3 | Sync auth spec |
| Sync envelope encryption | Server compromise | Sync Protocol | Vectors, parser fuzzing | MVP-3 | Sync spec |
| Metadata minimization | Server metadata leakage | Sync Server | Contract tests, data inventory | MVP-3 | Metadata inventory |
| Parser fuzzing | Malformed input | Parsers | cargo-fuzz/AFL++ | MVP-0+ | Fuzz corpus/report |
| Native messaging validation | Browser-to-native abuse | Native Host | Schema tests, fuzzing | MVP-4 | NM protocol tests |
| CLI shell-history protections | Secret leakage via argv | CLI | Unsafe argv rejection tests | MVP-0 | CLI safety spec |
| Encrypted .arcexp export | Plaintext backup leakage | CLI, Vault Engine | Export/import vectors | MVP-0/1 | `.arcexp` format spec |
| Static dependency audit | Supply-chain | CI/Release | cargo-audit/deny | MVP-0 | CI report |
| Signed releases | Release tampering | Release engineering | Signature verification | Beta | Release checklist |
| SBOM | Dependency visibility | Release engineering | SBOM generation | Beta | SBOM file |
| Formal protocol model | Protocol design errors | Security architecture | ProVerif/TLA+/Tamarin | MVP-2/3/Beta | Model files |

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

Arcanum must never claim:
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

## 5. Formal Verification Roadmap

| Priority | Tool | Scope | Phase | Artifact |
|---:|---|---|---:|---|
| Required | ProVerif | Transfer protocol secrecy/authentication | MVP-2 | `transfer_protocol.pv` |
| Required | TLA+ | Sync state machine, version vectors, conflict preservation | MVP-3 | `sync_state_machine.tla` |
| Beta target | Tamarin | Device pairing, replay, downgrade, revocation | Beta | `device_pairing.spthy` |
| Beta target | Kani | Selected Rust parsing invariants and fail-closed behavior | Beta | verification harnesses |
| Research | Creusot / Coq | High-assurance Rust logic | Research | proof artifacts |

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

## 7. Side-Channel Scope

### In Scope
- Timing leakage awareness in crypto-boundary code
- Constant-time helper APIs
- Avoiding secret-dependent branching and memory access
- Reviewing PQC backend side-channel claims
- Future dudect-style timing tests

### Out of Scope (MVP)
- Power analysis resistance
- Electromagnetic leakage resistance
- Fault injection resistance
- Speculative execution attack resistance
- Cache side-channel across hostile co-tenant workloads
- Hardware implant resistance
