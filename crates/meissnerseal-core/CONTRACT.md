# Contract: meissnerseal-core

**Version:** 0.1.0
**API Status:** Unstable — per ADR-025, Stable requires F-01/F-02/F-03/F-09/F-10/F-11 resolved and re-reviewed  
**Spec authority:** specs/protocol/vault_format_v1.md, transfer_profile_v1.md,
                   sync_profile_v1.md, recovery_kit_v1.md  
**ADRs:** ADR-001 through ADR-010, ADR-025 (implement-not-rescope), ADR-026 (locked create result), ADR-033 (vault typestate)

---

## Public API Surface

```
vault::
  Vault<Locked>::create(params: CreateVaultParams) -> Result<Vault<Locked>>
  Vault<Locked>::open(path) -> Result<Vault<Locked>>
  Vault<Locked>::unlock(self, params: UnlockParams) -> Result<Vault<Unlocked>>
         // UnlockParams { path: PathBuf, password: SecretBytes }
  Vault<Unlocked>::lock(self) -> Vault<Locked>

item::
  add(vault: &Vault<Unlocked>, item: PlainItem) -> Result<ItemId>
  with_item<F, R>(vault, item_id, f: F) -> Result<R>
    // F: FnOnce(&PlainItemView<'_>) -> Result<R>
  update(vault, item_id, item: PlainItem) -> Result<()>
  delete(vault, item_id) -> Result<()>
  list(vault) -> Result<Vec<ItemSummary>>

export::
  export(vault: &Vault<Unlocked>, passphrase: &[u8]) -> Result<Vec<u8>>
  import(vault: &Vault<Unlocked>, bundle: &[u8], passphrase: &[u8]) -> Result<Vec<ItemId>>

keys::device::
  DeviceIdentity
  DeviceKeypair
  DeviceTrustState
  generate(display_name: String) -> Result<(DeviceIdentity, DeviceKeypair)>
  try_new_ed25519_signing_public_key(bytes: [u8; 32]) -> Result<SigningPublicKey>
  try_new_signing_public_key(algorithm, bytes: &[u8]) -> Result<SigningPublicKey>
  sign_enrollment_message(private_key, message) -> Result<Signature>

```

---

## Planned (post-MVP-0)

These APIs are not part of the MVP-0 Stable contract. They will be locked
in future milestones as noted.

```
transfer::  [MVP-2 — PQC-dependent, meissnerseal-pqc not Stable]
  create_envelope(session, params) -> Result<TransferEnvelope>
  receive_envelope<F, R>(session, envelope, f: F) -> Result<R>
    // F: FnOnce(&PlainItemBundleView<'_>) -> Result<R>

device::  [post-MVP-0 — pairing/sync roadmap-excluded]
  pair(session, pairing_payload) -> Result<DeviceIdentity>
  approve(session, device_id) -> Result<()>
  revoke(session, device_id) -> Result<()>
  list(session) -> Result<Vec<DeviceIdentity>>

recovery::  [MVP-1 — ADR-010]
  generate_kit(session, params) -> Result<RecoveryKit>
  restore(vault_path, recovery_secret, new_password) -> Result<()>
```

### Planned Guarantees

```
[G-03] DeviceTrustState transitions are validated.  [post-MVP-0 — device::]
       Approved devices always have a signing_public_key.
       Transition to Approved with None signing key returns Err.

[G-04] transfer::receive_envelope rejects:  [MVP-2 — transfer::]
       — expired envelopes (expires_at in the past)
       — replayed envelope_ids
       — transcript hash mismatches
       — unknown or mismatched algorithm IDs
```

### Planned Preconditions

```
[P-03] RecoveryKit must be generated at vault creation or first unlock.  [MVP-1 — recovery::]
       Delayed generation is not supported in MVP.
```

---

## Guarantees

```
[G-01] Vault writes are crash-safe:
       serialize → encrypt → temp file → fsync → rename → fsync parent

[G-02] item::with_item uses scoped access. PlainItemView lifetime is
       bounded to the closure. Owned plaintext is not returned.

[G-05] Vault parser rejects:
       — wrong magic bytes
       — unknown critical TLV tags
       — truncated sections
       — trailing garbage

[G-06] All error paths return Err. No partial output on security failure.
```

---

## Anti-Guarantees

```
[A-01] Does NOT implement cryptographic operations directly.
       All crypto goes through meissnerseal-crypto and meissnerseal-pqc APIs.

[A-02] Does NOT protect plaintext against local malware or kernel compromise.

[A-03] Revocation does NOT erase secrets the revoked device already decrypted.
       This limitation is documented in the threat model.
```

---

## Preconditions

```
[P-01] Vault<Unlocked> must be obtained through Vault<Locked>::unlock only.
       Callers must not construct Vault<Unlocked> directly. Vault<Locked>
       carries no key material and cannot be passed to item/export operations.

[P-02] AAD passed to internal encryption calls must use the canonical
       construction from specs/protocol/vault_format_v1.md §7.

[P-04] UnlockedKeys contains all seven HKDF subkeys from
       specs/crypto/crypto_design.md §5:
       item-wrap, metadata, audit, sync-envelope, device-enroll,
       recovery-wrap, export-bundle.

[P-05] export:: export/import passphrase must be non-empty user-supplied
       secret material for the .msexp bundle. It is independent from vault
       master passwords and vault-internal HKDF subkeys.
```

---

## Invariants

```
[I-01] This crate never calls meissnerseal-pqc directly from business logic.
       PQC is called through the transfer protocol module only.

[I-02] This crate never writes plaintext to disk, logs, or error messages.

[I-03] Item metadata (label, tags) is encrypted where possible.
       Cleartext metadata in vault format is limited to what is
       required for unlock and migration.
```
