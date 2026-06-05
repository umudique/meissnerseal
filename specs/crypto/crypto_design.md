# Arcanum — Cryptographic Design

**Document status:** Specification  
**Spec version:** v4.0  
**Test vectors:** `test-vectors/vault_kdf_v1.json`, `test-vectors/transfer_hybrid_v1.json`

---

## 1. Primitive Registry

### Data-at-Rest

| Purpose | Primitive | Profile ID |
|---|---|---|
| Password KDF | Argon2id | `KDF_ARGON2ID_V1 = 0x0001` |
| Default AEAD | XChaCha20-Poly1305 | `AEAD_XCHACHA20_POLY1305_V1 = 0x0001` |
| Strict optional AEAD | AES-256-GCM | `AEAD_AES_256_GCM_STRICT_V1 = 0x0002` |
| Key derivation | HKDF-SHA256 / HKDF-SHA384 | per protocol profile |
| Randomness | OS CSPRNG | — |
| Secret comparison | Constant-time | — |
| Key zeroization | zeroize crate | — |

### Transfer

| Purpose | Primitive | Profile |
|---|---|---|
| Classical KEM | X25519 ephemeral | `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1` |
| PQC KEM | ML-KEM-768 | default; ML-KEM-1024 future |
| Transcript hash | SHA-256 (32 bytes) | MVP profile |
| HKDF extraction | HKDF-SHA256 | MVP profile |
| Transfer AEAD | XChaCha20-Poly1305 | default |

**Custom RNG is forbidden.** Arcanum must use OS CSPRNG exclusively.  
**Custom cryptographic primitives are forbidden.**

---

## 2. Argon2id KDF Profile v1

**Profile ID:** `KDF_ARGON2ID_V1 = 0x0001`

| Parameter | Value | Rationale |
|---|---|---|
| `m_cost_kib` | `65536` (64 MiB) | OWASP-aligned baseline, upgradeable |
| `t_cost` | `3` | Conservative for interactive unlock |
| `p_lanes` | `4` | Desktop parallelism |
| `output_len` | `32` bytes | 256-bit Master Unlock Key |
| `argon2_version` | `0x13` | Current Argon2 version |
| Salt | `"arcanum-argon2id-salt-v1" \|\| vault_id` | Domain-separated, vault-specific |

**Salt construction:**
```
argon2_salt = "arcanum-argon2id-salt-v1" || vault_id[16 bytes]
```

All parameters are stored in the vault header TLV (see [vault_format_v1.md](../protocol/vault_format_v1.md)). Implementations must:
- Read parameters from the vault header on unlock, not hardcode them
- Reject unsupported Argon2 versions
- Reject zero-valued cost parameters
- Enforce implementation memory/CPU safety limits

---

## 3. Key Hierarchy

```
Master Password
  └─ Argon2id(vault_id, kdf_params)
     └─ Master Unlock Key (32 bytes)
        └─ Vault Key Encryption Key
           └─ Wrapped Vault Root Key

Vault Root Key
  └─ HKDF domain-separated subkeys:
     ├─ Item Key Wrapping Key
     ├─ Metadata Encryption Key
     ├─ Local Audit Event Key
     ├─ Sync Envelope Key
     ├─ Device Enrollment Key
     ├─ Recovery Wrapping Key
     └─ Export Bundle Key

Each Item Revision
  └─ Fresh random Record Encryption Key (32 bytes, OS CSPRNG)
     └─ Item Payload encrypted with AEAD
     └─ Record Key wrapped by Item Key Wrapping Key

Transfer
  └─ X25519 Shared Secret
  └─ ML-KEM Shared Secret
  └─ HKDF-SHA256-Extract(transcript_hash_sha256, x_secret || pq_secret)
     └─ Transfer Payload Key (32 bytes)
```

---

## 4. HKDF Domain Separation Registry v1

**Root PRK derivation:**
```
root_prk = HKDF-SHA256-Extract(
  salt = SHA256("arcanum-root-salt-v1" || vault_id || header_nonce),
  ikm  = vault_root_key
)
```

**Derived keys** — each HKDF-SHA256-Expand call uses a unique `info` string:

| Derived Key | info string |
|---|---|
| Item Key Wrapping Key | `arcanum:item-wrap:v1:vault:{vault_id}:aead:{aead_id}` |
| Metadata Encryption Key | `arcanum:metadata:v1:vault:{vault_id}:aead:{aead_id}` |
| Local Audit Event Key | `arcanum:audit:v1:vault:{vault_id}` |
| Sync Envelope Key | `arcanum:sync-envelope:v1:vault:{vault_id}` |
| Device Enrollment Key | `arcanum:device-enroll:v1:vault:{vault_id}` |
| Recovery Wrapping Key | `arcanum:recovery-wrap:v1:vault:{vault_id}` |
| Export Bundle Key | `arcanum:export-bundle:v1:vault:{vault_id}` |

**Rules:**
- Every info string must include a version component.
- Future variable-length fields in info strings must be length-prefixed.
- Adding a new derived key requires a new info string and new test vectors.

---

## 5. Nonce Policy v1

### Default: `AEAD_XCHACHA20_POLY1305_V1`

- **Nonce length:** 192 bits
- **Source:** OS CSPRNG — centralized, non-overridable
- **Key policy:** Fresh random Record Encryption Key per encrypted record revision
- **Collision response:** Not reliably detectable; prevention is the only defense

### Strict optional: `AEAD_AES_256_GCM_STRICT_V1`

- **Nonce length:** 96 bits
- **Condition:** May only be used with a fresh random Record Encryption Key per revision
- **Forbidden:** Reusing the same Record Encryption Key for multiple AES-GCM encryptions
- **Forbidden:** Caller-supplied nonces outside test-only modules

### Sync nonce domain separation

Each edit is an immutable record revision with:
- New `revision_id`
- New Record Encryption Key
- New random nonce
- AAD including `device_id` (sync envelopes), `revision_id`, algorithm profile

This converts sync concurrency into a conflict-resolution problem, not an AEAD nonce-reuse problem.

---

## 6. Hybrid Key Derivation — Transfer Profile v1

**Profile:** `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1`

```
x_secret  = X25519(sender_ephemeral_private, recipient_static_public)
pq_secret = ML-KEM-768.Decapsulate(recipient_mlkem_private, pq_ciphertext)

hybrid_secret = HKDF-SHA256-Extract(
  salt = transcript_hash_sha256,   # 32 bytes
  ikm  = x_secret || pq_secret
)

transfer_key = HKDF-SHA256-Expand(
  prk    = hybrid_secret,
  info   = "arcanum-transfer-v1",
  length = 32
)
```

**Transcript hash binds:**
- Protocol version and profile ID
- Classical algorithm identifier (X25519)
- PQC algorithm identifier (ML-KEM-768)
- Sender device identity
- Recipient device identity or public key
- Classical ephemeral public key
- PQC ciphertext
- Envelope metadata
- Expiry metadata
- Context string `"arcanum-transfer-v1"`

**Downgrade resistance:** Any mismatch must reject the transfer before plaintext recovery.

**SHA-384 note:** HKDF-SHA384 and 48-byte transcript hashes are reserved for a future profile (`TRANSFER_HYBRID_X25519_MLKEM1024_SHA384_V2`). They must not be mixed into the v1 format.

---

## 7. Post-Quantum Use Cases

| Use Case | PQC Role | Profile |
|---|---|---|
| Device pairing | Hybrid key agreement | ML-KEM-768 |
| Secure transfer | Hybrid recipient encryption | `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1` |
| Sync device enrollment | Hybrid wrapping of device sync keys | ML-KEM-768 |
| Shared vault invitations | Hybrid envelope encryption | ML-KEM-768 |
| Long-lived recovery packets | Optional PQC recipient wrapping | Future |
| Release signatures | Future ML-DSA or classical + PQC | Future |

**Implementation rules:**
- Use ML-KEM for key encapsulation; ML-DSA only where signatures are required
- Do not implement PQC primitives from scratch
- Prefer narrow, maintained PQC backends
- Document all algorithm identifiers and parameters

---

## 8. Boundary Rules

- No custom cryptographic primitives
- No unauthenticated encryption anywhere
- No direct primitive calls from UI or sync server business logic
- Algorithm identifiers must be authenticated where they affect security
- All cryptographic formats must be versioned and have test vectors
- Every protocol profile must have a named profile ID

---

## 9. Security Claims

**Arcanum may claim:**
- Local-first encrypted vault
- Zero-knowledge encrypted sync
- Hybrid post-quantum-ready transfer
- Crypto-agile vault format
- Fuzz-tested parsers (only after fuzz targets run in CI)

**Arcanum must not claim:**
- Unhackable security
- Military-grade quantum encryption
- Absolute quantum-proof protection
- Resistance to all side channels
- Full production security before external review

---

## 10. Test Vector Requirements

| Vector file | Contents |
|---|---|
| `test-vectors/vault_kdf_v1.json` | Argon2id KDF_ARGON2ID_V1 input/output pairs |
| `test-vectors/vault_format_v1.json` | Vault header parse/serialize round-trips |
| `test-vectors/transfer_hybrid_v1.json` | TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1 |
| `test-vectors/sync_envelope_v1.json` | Sync envelope encryption/decryption |
| `test-vectors/recovery_kit_v1.json` | Recovery secret derivation and unwrapping |

All vectors must be independently cross-verified (SageMath or Python reference implementation).
