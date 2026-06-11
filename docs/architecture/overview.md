<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Arcanum — System Architecture Overview

**Document status:** Architecture reference  
**Spec version:** v4.0

---

## 1. Product Positioning

Arcanum is a local-first critical secrets vault and secure transfer platform. It is not a general password manager.

**Primary positioning:**
> Local-first vault and secure transfer for critical secrets, ready for the post-quantum era.

**Target users:**
- Developers and indie hackers (SSH keys, API tokens, `.env` files)
- Crypto operators (seed phrases, validator keys, wallet backups)
- Security-conscious small teams (self-hosted sync, audit trails)

**Arcanum is not:**
- A browser autofill password manager
- A cloud-first SaaS vault
- A product claiming resistance to all physical side-channel attacks

---

## 2. Core Principles

| Principle | Description |
|---|---|
| Local-first | Secrets remain on the user's device by default. No cloud account required. |
| Zero-knowledge sync | Sync server stores only encrypted blobs. Never receives plaintext or vault keys. |
| Crypto agility | Vault format and protocols support future cryptographic upgrades. |
| Conservative cryptography | Known primitives, reviewed implementations, no custom crypto. |
| PQC where it matters | PQC for device pairing, transfer, sync key wrapping. Not for local AEAD. |
| Open specifications | Threat model, vault format, transfer/sync protocols are public. |
| Security assurance as architecture | Every security claim maps to a component, test, and evidence artifact. |
| Secret lifecycle minimization | Plaintext exists for the shortest duration in the narrowest scope. |
| Failed-closed boundaries | Unknown algorithm, transcript mismatch, ambiguous trust state → reject. |
| Evidence-driven claims | No security claim without implementation, tests, docs, and review. |

---

## 3. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Arcanum Platform                         │
│                                                                 │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌────────────┐  │
│  │  Desktop  │  │   CLI     │  │  Mobile   │  │  Browser   │  │
│  │  (Flutter)│  │  (Rust)   │  │  (Flutter)│  │ Extension  │  │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬──────┘  │
│        │              │              │               │          │
│        └──────────────┴──────────────┴───────────────┘          │
│                              │                                  │
│                    ┌─────────▼──────────┐                       │
│                    │    Rust Core       │                       │
│                    │  arcanum-core      │                       │
│                    │  arcanum-crypto    │                       │
│                    │  arcanum-pqc       │                       │
│                    │  arcanum-security  │                       │
│                    └─────────┬──────────┘                       │
│                              │                                  │
│               ┌──────────────┼──────────────┐                  │
│               ▼              ▼              ▼                   │
│        ┌─────────┐   ┌────────────┐  ┌──────────┐             │
│        │  Vault  │   │  Local DB  │  │  Sync    │             │
│        │  File   │   │  (SQLite)  │  │  Server  │             │
│        │(.arcv)  │   │            │  │          │             │
│        └─────────┘   └────────────┘  └──────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

**Security Capability Layer** cuts across all components:

```
Security Capability Layer
  ├─ Secret Lifecycle Management
  ├─ Cryptographic Boundary
  ├─ PQC / Hybrid Protocol Boundary
  ├─ Hardware-Backed Protection Adapter
  ├─ Side-Channel Awareness Boundary
  ├─ Secure Observability
  └─ Failed-Closed Error Handling
```

---

## 4. C4 Level 1 — System Context

### Actors

| Actor | Description |
|---|---|
| Individual User | Stores and transfers critical secrets locally |
| Developer | Uses CLI, SSH/API key vault, encrypted transfer |
| Crypto Operator | Stores seed phrases, wallet backups, validator secrets |
| Team Admin | Manages shared vaults and approved devices |
| Security Reviewer | Reviews source code, threat model, protocol docs |
| Sync Service Operator | Operates managed encrypted sync without plaintext access |

### External Systems

| System | Purpose |
|---|---|
| OS Secure Storage | Keychain, Keystore, DPAPI, TPM-backed key wrapping |
| Web Browser | Hosts the Arcanum extension |
| Source Repository | Open-source distribution and review |
| Object Storage | Optional encrypted blob storage for sync |
| Payment Provider | Managed sync subscription billing |
| Security Audit Provider | Independent review |
| CI/CD Platform | Tests, static analysis, fuzz smoke, release gates |

---

## 5. C4 Level 2 — Containers

| Container | Technology | Responsibility |
|---|---|---|
| Rust Core Library | Rust | Cryptography, vault format, transfer/sync protocols |
| CLI | Rust | Developer workflows, automation, vault operations |
| Desktop App | Flutter + Rust FFI | Cross-platform GUI for vault and transfer |
| Mobile App | Flutter + Rust FFI | Mobile vault access and device pairing |
| Browser Extension | TypeScript WebExtension | Manual fill, browser integration |
| Native Messaging Host | Rust | Secure bridge between browser and local vault |
| Sync Server | Rust or Go | Encrypted blob sync, device registry |
| Managed Service Layer | Backend services | Billing, accounts, monitoring |
| Security Assurance Pipeline | CI + tooling | Static analysis, fuzzing, protocol verification, release gates |
| Local Vault File | Encrypted binary `.arcv` | User secrets at rest |
| Local Metadata DB | SQLite | Non-secret indexes, sync state, preferences |

---

## 6. C4 Level 3 — Rust Core Components

| Component | Responsibility |
|---|---|
| Vault Engine | Open, save, migrate, and validate vault files |
| Crypto Provider | AEAD, KDF, HKDF, random generation, secret comparison |
| PQC Provider | ML-KEM / ML-DSA wrappers and hybrid derivation |
| Key Manager | Key hierarchy, item keys, wrapping keys, device keys |
| Item Store | CRUD operations for encrypted items |
| File Bundle Manager | Encrypted file attachments and bundles |
| Transfer Protocol | Transfer envelopes, recipient encryption, replay protection |
| Sync Protocol | Blob envelopes, device state, conflict metadata |
| Device Manager | Device identity, pairing, approval, revocation |
| Recovery Manager | Emergency kit, recovery phrase |
| Policy Engine | Local policies, lock timeout, clipboard behavior |
| Audit Event Writer | Local non-secret event logging |
| Secret Lifecycle Manager | Plaintext lifetime, zeroization, redaction, session scope |
| Hardware Protection Adapter | OS secure storage, TPM/Secure Enclave abstraction |
| Side-Channel Guardrails | Constant-time helpers, secret-independent coding policy |
| Serialization Layer | Canonical encoding and versioned schema |
| Migration Manager | Vault format upgrades |
| FFI Layer | Safe API exposed to Flutter and native host |

---

## 7. C4 Level 4 — Crate Structure

```
crates/
  arcanum-core/
    src/
      vault/         engine.rs, format.rs, migration.rs
      item/          model.rs, store.rs, types.rs
      keys/          hierarchy.rs, wrapping.rs, device.rs
      transfer/      envelope.rs, protocol.rs, pairing.rs
      sync/          envelope.rs, state.rs, conflict.rs
      recovery/      emergency_kit.rs
      policy/        local_policy.rs
      audit/         event.rs
      error.rs

  arcanum-crypto/
    src/
      aead.rs        XChaCha20-Poly1305 (default), AES-256-GCM (strict)
      argon2.rs      KDF_ARGON2ID_V1
      hkdf.rs        HKDF domain separation registry
      rng.rs         OS CSPRNG wrapper — no custom RNG
      subtle.rs      constant-time helpers
      zeroize.rs     zeroization policy
      test_vectors.rs

  arcanum-pqc/
    src/
      mlkem.rs       ML-KEM-768 (default), ML-KEM-1024 (future)
      mldsa.rs       ML-DSA signatures (future)
      hybrid.rs      TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1
      backend.rs     PQC library adapter

  arcanum-security/
    src/
      secret_lifecycle.rs
      redaction.rs
      policy.rs
      hardware.rs    OS Keychain / Keystore / DPAPI / TPM adapter
      side_channel.rs
      audit_guard.rs

  arcanum-ffi/
    src/
      api.rs         VaultSessionHandle, SecretViewHandle
      error.rs
      memory.rs      FFI allocation and cleanup semantics

  arcanum-cli/
    src/
      main.rs        binary: arcanum
      commands/      init, add, get, list, transfer, device, export

  arcanum-sync-server/
    src/
      main.rs        binary: arcanum-server
      api/           authenticated endpoints
      devices/       device registry
      blobs/         encrypted blob store adapter
      accounts/      managed account metadata
      relay/         transfer relay
      rate_limit/    abuse prevention

fuzz/
  fuzz_targets/
    vault_header.rs, encrypted_item.rs, transfer_envelope.rs
    sync_envelope.rs, device_pairing.rs, native_message.rs

specs/
  protocol/          vault_format_v1, transfer_profile_v1, sync_profile_v1
  crypto/            crypto_design
  security/          threat_model, security_assurance
  formal/            transfer_protocol.pv, sync_state_machine.tla

test-vectors/
  vault_kdf_v1.json, vault_format_v1.json
  transfer_hybrid_v1.json, sync_envelope_v1.json
  recovery_kit_v1.json
```

---

## 8. Platform Strategy

| Layer | Technology |
|---|---|
| Cryptographic core | Rust |
| CLI | Rust |
| Desktop UI | Flutter |
| Mobile UI | Flutter |
| Browser extension | TypeScript WebExtension |
| Browser bridge | Native messaging host in Rust |
| Optional browser crypto | Rust/WASM |
| Sync backend | Rust or Go |
| Local metadata | SQLite |
| Server metadata | PostgreSQL |
| Blob storage | S3-compatible or local filesystem |
| Deployment | Docker Compose → Kubernetes |

---

## 9. Security Boundaries

**Trusted local boundary:** arcanum-core, arcanum-crypto, arcanum-pqc, arcanum-security, arcanum-ffi, arcanum-cli

**Untrusted boundary:** Browser extension, relay server, sync server, managed service layer, OS accessibility APIs

**Dart/Flutter is not part of the trusted secret-memory boundary.** Plaintext crossing FFI into Dart heap is subject to GC timing and OS swap. See [ADR-004](../adr/ADR-004-handle-lease-ffi.md).

---

## 10. Related Documents

- [MVP Roadmap](mvp_roadmap.md)
- [Cryptographic Design](../../specs/crypto/crypto_design.md)
- [Threat Model](../../specs/security/threat_model.md)
- [Security Assurance](../../specs/security/security_assurance.md)
- [Vault Format v1](../../specs/protocol/vault_format_v1.md)
- [Transfer Profile v1](../../specs/protocol/transfer_profile_v1.md)
- [Sync Profile v1](../../specs/protocol/sync_profile_v1.md)
