<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# MeissnerSeal — Cryptographic Design

**Document status:** Specification  
**Spec version:** v4.0  
**Test vectors:** `test-vectors/vault_kdf_v1.json`, `test-vectors/transfer_hybrid_v1.json`  
**Security claims:** See [security_assurance.md](../security/security_assurance.md)

---

## 1. Primitive Registry

### Data-at-Rest

| Purpose | Primitive | Profile ID |
|---|---|---|
| Password KDF | Argon2id | `KDF_ARGON2ID_V1 = 0x0001` |
| Default AEAD | XChaCha20-Poly1305 | `AEAD_XCHACHA20_POLY1305_V1 = 0x0001` |
| Strict optional AEAD | AES-256-GCM | `AEAD_AES_256_GCM_STRICT_V1 = 0x0002` |
| Key derivation | HKDF-SHA256 | default; HKDF-SHA384 future profiles only |
| Randomness | OS CSPRNG | — |
| Secret comparison | Constant-time | `subtle` crate |
| Key zeroization | `zeroize` crate | — |

### Transfer

| Purpose | Primitive | Profile |
|---|---|---|
| Classical KEM | X25519 ephemeral | `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1` |
| PQC KEM | ML-KEM-768 | default; ML-KEM-1024 future |
| Transcript hash | SHA-256 (32 bytes) | MVP profile |
| HKDF | HKDF-SHA256 | MVP profile |
| Transfer AEAD | XChaCha20-Poly1305 | default |

**Rules:**
- Custom RNG is forbidden. MeissnerSeal must use OS CSPRNG exclusively.
- Custom cryptographic primitives are forbidden.
- HKDF-SHA384 is reserved for future profiles; must not appear in v1 formats.

---

## 2. Argon2id KDF Profile v1

**Profile ID:** `KDF_ARGON2ID_V1 = 0x0001`

| Parameter | Value | Rationale |
|---|---|---|
| `m_cost_kib` | `65536` (64 MiB) | OWASP-aligned baseline, upgradeable |
| `t_cost` | `3` | Conservative for interactive unlock |
| `p_lanes` | `4` | Desktop parallelism |
| `output_len` | `32` bytes | 256-bit Master Unlock Key |
| `argon2_version` | `0x13` | Current Argon2 version identifier |
| Salt | `"meissnerseal-argon2id-salt-v1" \|\| vault_id` | Domain-separated, vault-specific |

**Salt construction** — fixed-width concatenation, no length ambiguity:
```
argon2_salt = b"meissnerseal-argon2id-salt-v1"  # 24 bytes, ASCII
           || vault_id                      # 16 bytes, raw UUID bytes
                                            # = 40 bytes total
```

All parameters are stored in the vault header TLV. Implementations must:
- Read parameters from vault header on unlock — never hardcode them
- Reject unsupported Argon2 versions
- Reject zero-valued cost parameters
- Enforce memory/CPU safety limits against DoS via large parameter values

---

## 3. Key Hierarchy

Every step in the key hierarchy is fully specified below.
No step may be left to implementation discretion.

```
Master Password
  └─[1]─ Argon2id(KDF_ARGON2ID_V1, salt="meissnerseal-argon2id-salt-v1"||vault_id)
          └─ Master Unlock Key (MUK, 32 bytes)

Master Unlock Key
  └─[2]─ HKDF-SHA256-Extract(salt=b"meissnerseal-vkek-salt-v1"||vault_id, ikm=MUK)
          └─ vault_kek_prk
  └─[3]─ HKDF-SHA256-Expand(prk=vault_kek_prk, info="meissnerseal:vault-kek:v1", length=32)
          └─ Vault Key Encryption Key (VKEK, 32 bytes)

Vault Key Encryption Key
  └─[4]─ XChaCha20-Poly1305(key=VKEK, nonce=vkek_nonce, aad=vault_header_aad)
          └─ Wrapped Vault Root Key  [stored in WrappedRootKey record]
          └─ vkek_nonce              [stored in WrappedRootKey record frame]

Vault Root Key (VRK, 32 bytes)
  └─[5]─ HKDF-SHA256-Extract(salt=SHA256("meissnerseal-root-salt-v1"||vault_id||header_nonce), ikm=VRK)
          └─ root_prk
  └─[6]─ HKDF-SHA256-Expand(root_prk, info=<see registry>, length=32) × 7
          ├─ Item Key Wrapping Key (IKWK)
          ├─ Metadata Encryption Key (MEK)
          ├─ Local Audit Event Key (LAEK)
          ├─ Sync Envelope Key (SEK)
          ├─ Device Enrollment Key (DEK)
          ├─ Recovery Wrapping Key (RWK)
          └─ Export Bundle Key (EBK)

Each Item Revision
  └─[7]─ OS CSPRNG → Record Encryption Key (REK, 32 bytes, fresh per revision)
  └─[8]─ XChaCha20-Poly1305(key=REK, nonce=random_192bit, aad=record_aad)
          └─ Encrypted item payload
  └─[9]─ XChaCha20-Poly1305(key=IKWK, nonce=random_192bit, aad=wrap_aad)
          └─ Wrapped REK  [stored alongside encrypted payload in record frame]

Transfer
  └─[10]─ X25519(sender_ephemeral_private, recipient_static_public) → x_secret (32 bytes)
  └─[11]─ ML-KEM-768.Decapsulate(recipient_mlkem_private, pq_ciphertext) → pq_secret (32 bytes)
  └─[12]─ HKDF-SHA256-Extract(salt=transcript_hash_sha256, ikm=x_secret||pq_secret)
           └─ hybrid_prk
  └─[13]─ HKDF-SHA256-Expand(hybrid_prk, info="meissnerseal-transfer-v1", length=32)
           └─ Transfer Payload Key (TPK, 32 bytes)
```

---

## 4. Step-by-Step Specification

### Step 2–3: Master Unlock Key → Vault Key Encryption Key

```
# Step 2: Extract
vkek_salt = b"meissnerseal-vkek-salt-v1"  # 20 bytes, ASCII
          || vault_id                 # 16 bytes, raw bytes
                                      # = 36 bytes total (fixed-width, no length prefix needed)

vault_kek_prk = HKDF-SHA256-Extract(salt=vkek_salt, ikm=master_unlock_key)

# Step 3: Expand
vault_kek = HKDF-SHA256-Expand(
  prk    = vault_kek_prk,
  info   = b"meissnerseal:vault-kek:v1",   # 20 bytes, ASCII
  length = 32
)
```

Rationale: HKDF-Extract step ensures the MUK is properly conditioned as a PRK
before expansion, as required by RFC 5869, even though Argon2id output is
already uniformly random. This preserves the formal security proof of HKDF.

### Step 4: Vault Root Key Wrapping

The Vault Root Key is encrypted with XChaCha20-Poly1305 and stored as a
`WrappedRootKey` record in the vault file:

```
vkek_nonce    = 192-bit random (OS CSPRNG)
wrap_aad      = canonical AAD with record_kind = WrappedRootKey (0x0002)

ciphertext    = XChaCha20-Poly1305.Encrypt(
  key   = vault_kek,
  nonce = vkek_nonce,
  aad   = wrap_aad,
  plaintext = vault_root_key  # 32 bytes
)
```

`vkek_nonce` is stored in the encrypted record frame `nonce` field.
`ciphertext` is stored in the encrypted record frame `ciphertext` field.

On unlock: decrypt this record with `vault_kek` to recover `vault_root_key`.

### Steps 5–6: Vault Root Key → Subkeys

```
# Step 5: Root PRK
root_salt = SHA256(
  b"meissnerseal-root-salt-v1"  # 20 bytes
  || vault_id              # 16 bytes
  || header_nonce          # 24 bytes
)                          # SHA256 → 32 bytes

root_prk = HKDF-SHA256-Extract(salt=root_salt, ikm=vault_root_key)

# Step 6: One Expand call per subkey (see Section 5 for info strings)
subkey = HKDF-SHA256-Expand(prk=root_prk, info=<info_string>, length=32)
```

### Steps 7–9: Record Encryption

```
# Step 7: Fresh record key per revision
record_encryption_key = OS-CSPRNG(32 bytes)

# Step 8: Encrypt item payload
payload_nonce = OS-CSPRNG(24 bytes)  # 192-bit XChaCha20 nonce
encrypted_payload = XChaCha20-Poly1305.Encrypt(
  key       = record_encryption_key,
  nonce     = payload_nonce,
  aad       = canonical_record_aad,
  plaintext = item_payload_bytes
)

# Step 9: Wrap record key
wrap_nonce = OS-CSPRNG(24 bytes)
wrapped_rek = XChaCha20-Poly1305.Encrypt(
  key       = item_key_wrapping_key,
  nonce     = wrap_nonce,
  aad       = canonical_record_aad,  # same AAD binds both operations
  plaintext = record_encryption_key
)
```

Both `payload_nonce`, `wrapped_rek`, and `wrap_nonce` are stored in the record frame.

---

## 5. HKDF Domain Separation Registry v1

### Info String Encoding Rules

All info strings are ASCII byte sequences. Substituted values must use
the following canonical encodings to ensure deterministic reproduction:

| Field | Encoding |
|---|---|
| `{vault_id}` | lowercase hex string, 32 characters (e.g., `a1b2c3d4e5f6789012345678abcdef01`) |
| `{aead_id}` | decimal string of the u16 enum value (e.g., `1` for XChaCha20-Poly1305) |
| `{recovery_id}` | lowercase hex string, 32 characters |

Example: `meissnerseal:item-wrap:v1:vault:a1b2c3d4e5f6789012345678abcdef01:aead:1`

### Derived Key Info Strings

| Derived Key | Info String |
|---|---|
| Item Key Wrapping Key | `meissnerseal:item-wrap:v1:vault:{vault_id}:aead:{aead_id}` |
| Metadata Encryption Key | `meissnerseal:metadata:v1:vault:{vault_id}:aead:{aead_id}` |
| Local Audit Event Key | `meissnerseal:audit:v1:vault:{vault_id}` |
| Sync Envelope Key | `meissnerseal:sync-envelope:v1:vault:{vault_id}` |
| Device Enrollment Key | `meissnerseal:device-enroll:v1:vault:{vault_id}` |
| Recovery Wrapping Key | `meissnerseal:recovery-wrap:v1:vault:{vault_id}` |
| Export Bundle Key | `meissnerseal:export-bundle:v1:vault:{vault_id}` |

### Registry Rules

- Every info string must include a version component (`v1`, `v2`, …)
- Adding a new derived key requires a new info string and new test vectors
- Future variable-length substitutions must be length-prefixed before encoding

---

## 6. Nonce Policy v1

### Default: `AEAD_XCHACHA20_POLY1305_V1`

- **Nonce length:** 192 bits (24 bytes)
- **Source:** OS CSPRNG — centralized API, non-overridable by callers
- **Key policy:** Fresh Record Encryption Key per encrypted record revision
- **Collision bound:** With 192-bit nonces, birthday probability is negligible
  even at 2^64 records under the same key — but fresh record keys make this moot

### Strict optional: `AEAD_AES_256_GCM_STRICT_V1`

- **Nonce length:** 96 bits (12 bytes)
- **Condition:** Only with a fresh Record Encryption Key per revision
- **Forbidden:** Reusing the same Record Encryption Key for multiple AES-GCM encryptions
- **Forbidden:** Caller-supplied nonces outside `#[cfg(test)]` modules

### Sync nonce domain separation

Each edit creates an immutable record revision with:
- New `revision_id` (fresh 128-bit random)
- New Record Encryption Key (fresh 256-bit random)
- New random nonce
- AAD including `revision_id` and algorithm profile

This converts sync concurrency into a conflict-resolution problem, not an AEAD nonce-reuse problem.

---

## 7. Hybrid Key Derivation — Transfer Profile v1

**Profile:** `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1`

See steps 10–13 in Section 3. Full derivation:

```
x_secret     = X25519(sender_ephemeral_private, recipient_static_public)  # 32 bytes
pq_secret    = ML-KEM-768.Decapsulate(recipient_mlkem_private, pq_ciphertext)  # 32 bytes

hybrid_prk   = HKDF-SHA256-Extract(
  salt = transcript_hash_sha256,   # 32 bytes — see transfer_profile_v1.md
  ikm  = x_secret || pq_secret    # 64 bytes
)

transfer_key = HKDF-SHA256-Expand(
  prk    = hybrid_prk,
  info   = b"meissnerseal-transfer-v1",
  length = 32
)
```

**HKDF-SHA384 note:** Reserved for `TRANSFER_HYBRID_X25519_MLKEM1024_SHA384_V2`.
Must not appear in v1 envelope format. Profile mismatch → reject.

---

## 8. Post-Quantum Use Cases

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
- Prefer narrow, maintained PQC backends with constant-time claims
- Document all algorithm identifiers and parameters
- See `docs/ops/dependency_risk_register.md` for PQC library selection criteria

---

## 9. Cryptographic Boundary Rules

- No custom cryptographic primitives
- No unauthenticated encryption anywhere
- No direct primitive calls from UI or sync server business logic
- Algorithm identifiers must be authenticated where they affect security
- All cryptographic formats must be versioned and have test vectors
- Every protocol profile must have a named profile ID
- HKDF-Expand must only be called on output of HKDF-Extract (RFC 5869 compliance)

---

## 10. Test Vector Requirements

| Vector file | Contents |
|---|---|
| `test-vectors/vault_kdf_v1.json` | Argon2id: password + vault_id → MUK; MUK → VKEK; VRK wrapping/unwrapping |
| `test-vectors/vault_format_v1.json` | Header TLV round-trips; record frame AEAD; AAD construction |
| `test-vectors/transfer_hybrid_v1.json` | `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1` full derivation |
| `test-vectors/sync_envelope_v1.json` | Sync envelope AEAD; nonce domain separation |
| `test-vectors/recovery_kit_v1.json` | Bech32m encoding; recovery key derivation; passphrase hardening |

**All vectors must be independently cross-verified** (SageMath or Python reference
implementation) before being committed as authoritative.

### Required cases for `vault_kdf_v1.json`

- Argon2id: known password + vault_id → deterministic MUK output
- VKEK derivation: MUK + vault_id → deterministic VKEK output
- VRK wrapping: VKEK + VRK + nonce → ciphertext; decrypt back to VRK
- Root PRK: VRK + vault_id + header_nonce → deterministic root_prk
- Each subkey: root_prk + info_string → deterministic subkey output
- Rejection: zero m_cost → error; unsupported argon2_version → error
