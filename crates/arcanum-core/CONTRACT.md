# Contract: arcanum-core

**Version:** 0.1.0
**API Status:** Unstable  
**Spec authority:** specs/protocol/vault_format_v1.md, transfer_profile_v1.md,
                   sync_profile_v1.md, recovery_kit_v1.md  
**ADRs:** ADR-001 through ADR-010, ADR-025 (implement-not-rescope), ADR-026 (create returns VaultHandle)

---

## Public API Surface

```
vault::
  create(params: CreateVaultParams) -> Result<VaultHandle>
  unlock(path, master_secret) -> Result<VaultSession>
  lock(session: VaultSession) -> Result<()>

item::
  add(session: &VaultSession, item: PlainItem) -> Result<ItemId>
  with_item<F, R>(session, item_id, f: F) -> Result<R>
    // F: FnOnce(&PlainItemView<'_>) -> Result<R>
  update(session, item_id, item: PlainItem) -> Result<()>
  delete(session, item_id) -> Result<()>
  list(session) -> Result<Vec<ItemSummary>>

export::
  export(session: &VaultSession, passphrase: &[u8]) -> Result<Vec<u8>>
  import(session: &VaultSession, bundle: &[u8], passphrase: &[u8]) -> Result<Vec<ItemId>>

transfer::
  create_envelope(session, params) -> Result<TransferEnvelope>
  receive_envelope<F, R>(session, envelope, f: F) -> Result<R>
    // F: FnOnce(&PlainItemBundleView<'_>) -> Result<R>

device::
  pair(session, pairing_payload) -> Result<DeviceIdentity>
  approve(session, device_id) -> Result<()>
  revoke(session, device_id) -> Result<()>
  list(session) -> Result<Vec<DeviceIdentity>>

recovery::
  generate_kit(session, params) -> Result<RecoveryKit>
  restore(vault_path, recovery_secret, new_password) -> Result<()>
```

---

## Guarantees

```
[G-01] Vault writes are crash-safe:
       serialize → encrypt → temp file → fsync → rename → fsync parent

[G-02] item::with_item uses scoped access. PlainItemView lifetime is
       bounded to the closure. Owned plaintext is not returned.

[G-03] DeviceTrustState transitions are validated.
       Approved devices always have a signing_public_key.
       Transition to Approved with None signing key returns Err.

[G-04] transfer::receive_envelope rejects:
       — expired envelopes (expires_at in the past)
       — replayed envelope_ids
       — transcript hash mismatches
       — unknown or mismatched algorithm IDs

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
       All crypto goes through arcanum-crypto and arcanum-pqc APIs.

[A-02] Does NOT protect plaintext against local malware or kernel compromise.

[A-03] Revocation does NOT erase secrets the revoked device already decrypted.
       This limitation is documented in the threat model.
```

---

## Preconditions

```
[P-01] VaultSession must be obtained through vault::unlock only.
       Callers must not construct VaultSession directly.

[P-02] AAD passed to internal encryption calls must use the canonical
       construction from specs/protocol/vault_format_v1.md §7.

[P-03] RecoveryKit must be generated at vault creation or first unlock.
       Delayed generation is not supported in MVP.

[P-04] UnlockedKeys contains all seven HKDF subkeys from
       specs/crypto/crypto_design.md §5:
       item-wrap, metadata, audit, sync-envelope, device-enroll,
       recovery-wrap, export-bundle.

[P-05] export:: export/import passphrase must be non-empty user-supplied
       secret material for the .arcexp bundle. It is independent from vault
       master passwords and vault-internal HKDF subkeys.
```

---

## Invariants

```
[I-01] This crate never calls arcanum-pqc directly from business logic.
       PQC is called through the transfer protocol module only.

[I-02] This crate never writes plaintext to disk, logs, or error messages.

[I-03] Item metadata (label, tags) is encrypted where possible.
       Cleartext metadata in vault format is limited to what is
       required for unlock and migration.
```
