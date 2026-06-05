# Arcanum Recovery Kit v1

**Profile:** `QVRK_RECOVERY_SECRET_V1`
**Status:** Specification — MVP-1 (kit generation), MVP-3 (sync interaction)
**Fuzz target:** `fuzz/fuzz_targets/vault_header.rs` (kit header parsing)
**Test vectors:** `test-vectors/recovery_kit_v1.json`

---

## 1. Baseline Rule

> If the user loses the master password and has neither an approved unlocked device
> nor a valid recovery kit, the vault is **unrecoverable**.

Arcanum servers must not be able to reset or recover a zero-knowledge vault.
This limitation must be documented clearly in the product.

---

## 2. Recovery Secret Encoding v1

Arcanum uses a Bech32m-encoded recovery secret rather than BIP-39.
BIP-39 mnemonics imply compatibility with cryptocurrency seed phrases and
increase user confusion for a general vault product.

```
recovery_seed     = 32 bytes from OS CSPRNG
recovery_secret   = Bech32m(hrp="arc", data=profile_id || recovery_id || recovery_seed)
```

**Human-readable prefix (HRP):** `arc`  
**Checksum:** Bech32m (BCH-based, 6-character suffix)  
**Transcription:** lowercase alphanumeric, no ambiguous characters (0/O, 1/l/I)

Example format: `arc1<base32-encoded-data><6-char-checksum>`

---

## 3. Recovery Key Derivation

```
recovery_salt     = SHA256("arcanum-recovery-salt-v1" || vault_id || recovery_id)

recovery_prk      = HKDF-SHA256-Extract(
  salt = recovery_salt,
  ikm  = recovery_seed
)

recovery_wrap_key = HKDF-SHA256-Expand(
  prk    = recovery_prk,
  info   = "arcanum:recovery-wrap:v1:vault:{vault_id}:recovery:{recovery_id}",
  length = 32
)
```

---

## 4. Optional Passphrase Hardening

If the user enables a recovery passphrase, it is mixed into the PRK:

```
recovery_passphrase_key = Argon2id(
  passphrase,
  salt   = SHA256("arcanum-recovery-passphrase-v1" || vault_id || recovery_id),
  params = KDF_ARGON2ID_V1   (same parameter set as vault KDF)
)

recovery_prk = HKDF-SHA256-Extract(
  salt = recovery_salt,
  ikm  = recovery_seed || recovery_passphrase_key
)
```

The kit stores a flag indicating passphrase requirement — never the passphrase itself.

---

## 5. Emergency Kit Contents

The printed or encrypted kit file must include:

| Field | Purpose |
|---|---|
| `vault_id` | Identifies the vault |
| `recovery_id` | Identifies this recovery kit |
| `created_at` | Creation timestamp |
| `recovery_profile_version` | `QVRK_RECOVERY_SECRET_V1` |
| KDF/HKDF parameters | Required for derivation |
| `wrapped_vault_recovery_key` | Encrypted vault root key material |
| Bech32m recovery secret | `arc1...` string or QR code |
| Checksum/fingerprint | Manual verification |
| `passphrase_required` flag | Does not store the passphrase |
| Warning text | "Possession of this kit may unlock vault recovery" |

---

## 6. Recovery Flow

1. User selects recovery mode in the app
2. Client validates `vault_id` and recovery profile version
3. User enters/scans the `arc1...` recovery secret or imports encrypted kit file
4. Client validates Bech32m checksum, `vault_id`, `recovery_id`, profile version, passphrase flag
5. Client derives the Recovery Wrapping Key locally
6. Client unwraps the Vault Recovery Key locally
7. Client unwraps or re-wraps the Vault Root Key locally
8. User sets a new master password
9. New master password derives a new Master Unlock Key via KDF_ARGON2ID_V1
10. Vault Root Key is re-wrapped under the new hierarchy
11. A recovery event is written locally (no secret values)
12. If sync is enabled, approved devices are notified; new device enrollment may require approval

**Recovery must never require sending** master password, recovery secret,
vault root key, or unwrapped recovery key to a server.

---

## 7. Deferred Features

The following are **not** part of MVP and must not be implied in product messaging:
- Shamir Secret Sharing
- Social/guardian recovery
- Server-assisted recovery

These are future optional profiles requiring independent implementation and review.
