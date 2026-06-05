# Arcanum

**Local-first critical secrets vault with hybrid post-quantum-ready transfer.**

> **Alpha software. Do not store real secrets yet.**

Arcanum stores and transfers high-value secrets — seed phrases, SSH keys, API tokens, recovery codes, encrypted file bundles — using conservative local-first encryption and hybrid post-quantum-ready sharing protocols.

---

## What Arcanum Is

- A local-first vault for critical secrets
- A hybrid post-quantum-ready secure transfer system
- A developer-friendly CLI and desktop tool
- A self-hostable encrypted sync platform
- A security transparency project with public threat models and protocol specs

## What Arcanum Is Not

- A general browser autofill password manager
- A cloud-first SaaS vault
- A product claiming resistance to all physical side-channel attacks
- A "quantum magic" encryption product

---

## Documentation Index

### Architecture
| Document | Description |
|---|---|
| [docs/architecture/overview.md](docs/architecture/overview.md) | System overview, C4 diagrams, component map |
| [docs/architecture/mvp_roadmap.md](docs/architecture/mvp_roadmap.md) | MVP definitions, priority, and security roadmap |

### Protocol Specifications
| Document | Description |
|---|---|
| [specs/protocol/vault_format_v1.md](specs/protocol/vault_format_v1.md) | Binary wire format, TLV tags, record framing, AAD |
| [specs/protocol/transfer_profile_v1.md](specs/protocol/transfer_profile_v1.md) | Hybrid X25519+ML-KEM transfer, relay trust boundary |
| [specs/protocol/sync_profile_v1.md](specs/protocol/sync_profile_v1.md) | Sync conflict model, version vectors, device auth |
| [specs/protocol/recovery_kit_v1.md](specs/protocol/recovery_kit_v1.md) | Recovery secret encoding, emergency kit, flow |
| [specs/protocol/native_messaging_v1.md](specs/protocol/native_messaging_v1.md) | Browser native messaging protocol |

### Cryptographic Design
| Document | Description |
|---|---|
| [specs/crypto/crypto_design.md](specs/crypto/crypto_design.md) | Primitives, key hierarchy, HKDF registry, nonce policy |

### Security
| Document | Description |
|---|---|
| [specs/security/threat_model.md](specs/security/threat_model.md) | Assets, adversaries, scope |
| [specs/security/security_assurance.md](specs/security/security_assurance.md) | Control matrix, claims matrix, release gates |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy |

### Architecture Decisions
| Document | Decision |
|---|---|
| [docs/adr/ADR-001-xchacha20-default.md](docs/adr/ADR-001-xchacha20-default.md) | XChaCha20-Poly1305 as default AEAD |
| [docs/adr/ADR-002-version-vectors.md](docs/adr/ADR-002-version-vectors.md) | Version vectors over monotonic revision IDs |
| [docs/adr/ADR-003-bech32m-recovery.md](docs/adr/ADR-003-bech32m-recovery.md) | Bech32m encoding for recovery secrets |
| [docs/adr/ADR-004-handle-lease-ffi.md](docs/adr/ADR-004-handle-lease-ffi.md) | Handle-and-lease model for FFI/Dart plaintext |
| [docs/adr/ADR-005-formal-methods.md](docs/adr/ADR-005-formal-methods.md) | ProVerif MVP-2, TLA+ MVP-3, staged formal methods |
| [docs/adr/ADR-006-argon2id-params.md](docs/adr/ADR-006-argon2id-params.md) | KDF_ARGON2ID_V1 parameter set |
| [docs/adr/ADR-007-sha256-transcript.md](docs/adr/ADR-007-sha256-transcript.md) | SHA-256 transcript hash for MVP transfer profile |
| [docs/adr/ADR-008-arcexp-export.md](docs/adr/ADR-008-arcexp-export.md) | Encrypted .arcexp as default export format |
| [docs/adr/ADR-009-user-mediated-conflicts.md](docs/adr/ADR-009-user-mediated-conflicts.md) | No auto-merge for critical secrets |
| [docs/adr/ADR-010-unrecoverable-by-default.md](docs/adr/ADR-010-unrecoverable-by-default.md) | Vault unrecoverable without recovery kit |

### Formal Specifications
| Document | Tool | MVP Phase |
|---|---|---|
| [specs/formal/transfer_protocol.pv](specs/formal/transfer_protocol.pv) | ProVerif | MVP-2 |
| [specs/formal/sync_state_machine.tla](specs/formal/sync_state_machine.tla) | TLA+ | MVP-3 |
| [specs/formal/device_pairing.spthy](specs/formal/device_pairing.spthy) | Tamarin | Beta |

### Operations
| Document | Description |
|---|---|
| [docs/ops/release_checklist.md](docs/ops/release_checklist.md) | Release security gates and checklist |
| [docs/ops/incident_response.md](docs/ops/incident_response.md) | Vulnerability incident response runbook |
| [docs/ops/dependency_risk_register.md](docs/ops/dependency_risk_register.md) | Cryptographic dependency risk register |

---

## Workspace

```
crates/
  arcanum-core/         vault engine, item store, transfer/sync protocols
  arcanum-crypto/       AEAD, KDF, HKDF, RNG primitives
  arcanum-pqc/          ML-KEM, ML-DSA, hybrid key derivation
  arcanum-security/     secret lifecycle, redaction, hardware adapter
  arcanum-ffi/          Flutter/native host FFI boundary
  arcanum-cli/          developer CLI  (binary: arcanum)
  arcanum-sync-server/  encrypted blob sync server
fuzz/                   cargo-fuzz targets
specs/                  protocol and formal specifications
docs/                   architecture decisions and operations
test-vectors/           deterministic cryptographic test vectors
```

## License

AGPL-3.0-or-later
