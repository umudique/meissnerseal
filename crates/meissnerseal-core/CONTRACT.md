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
  UntrustedVaultFile
  UntrustedVaultFile::parse_and_validate(bytes: &[u8]) -> Result<UntrustedVaultFile>
  record_frame_end_offset(bytes: &[u8], offset: usize) -> Result<usize>
    // hidden parser-layout helper exposed for integration tests; not a
    // stable application-facing API
  Vault<Locked>::create(params: CreateVaultParams) -> Result<Vault<Locked>>
  Vault<Locked>::open(path) -> Result<Vault<Locked>>
  Vault<Locked>::unlock(self, params: UnlockParams) -> Result<Vault<Unlocked>>
         // UnlockParams { path: PathBuf, password: SecretBytes }
  Vault<Unlocked>::lock(self) -> Vault<Locked>

item::
  add(vault: &Vault<Unlocked>, item: PlainItem) -> Result<ItemId>
  with_item<F>(vault, item_id, f: F) -> Result<()>
    // SEC-6 Phase 2 handoff target:
    // F: FnOnce(&PlainItemView<'_>) -> Result<()>
  update(vault, item_id, item: PlainItem) -> Result<()>
  delete(vault, item_id) -> Result<()>
  list(vault) -> Result<Vec<ItemSummary>>

export::
  UntrustedExportBundle
  UntrustedExportBundle::authenticate(bundle: &[u8], passphrase: &[u8]) -> Result<UntrustedExportBundle>
  export(vault: &Vault<Unlocked>, passphrase: &[u8]) -> Result<Vec<u8>>
  import(vault: &Vault<Unlocked>, bundle: &[u8], passphrase: &[u8]) -> Result<Vec<ItemId>>

keys::device::
  DEVICE_ENROLLMENT_SIGNING_DOMAIN: &[u8]
    // b"meissnerseal.device.enrollment.v1\x00" — owned here, passed to mldsa P-04
  DeviceIdentity
  DeviceKeypair
  DeviceTrustState
  generate(display_name: String) -> Result<(DeviceIdentity, DeviceKeypair)>
  try_new_ed25519_signing_public_key(bytes: [u8; 32]) -> Result<SigningPublicKey>
  try_new_signing_public_key(algorithm, bytes: &[u8]) -> Result<SigningPublicKey>
  enrollment_signing_message(message: &[u8]) -> Vec<u8>
    // convenience: prepends DEVICE_ENROLLMENT_SIGNING_DOMAIN || message
  sign_enrollment_message(private_key, message: &[u8]) -> Result<Signature>
    // calls mldsa::sign_with_domain with DEVICE_ENROLLMENT_SIGNING_DOMAIN
  SealedDeviceKeyFile
  SealedDeviceKeyFile::seal(identity, keypair, dkek: &AeadKey) -> Result<Zeroizing<Vec<u8>>>
  SealedDeviceKeyFile::open(bytes, dkek: &AeadKey) -> Result<(DeviceIdentity, DeviceKeypair)>
  create_signed_transfer_envelope(
    sender_device_id, sender_keypair, recipient_device_id,
    recipient_classical_public_key, recipient_pqc_public_key,
    plaintext: SecretPayload, expires_at) -> Result<TransferEnvelope, TransferError>
    // convenience wrapper over transfer::create_envelope
  open_received_transfer_envelope(
    envelope, recipient_keypair, recipient_classical_public_key,
    sender: TrustedSender, seen: &mut SeenEnvelopeIds)
    -> Result<SecretPayload, TransferError>
    // convenience wrapper over transfer::open_envelope

keys::pairing::
  DEVICE_PAIRING_SIGNING_DOMAIN: &[u8]
    // b"meissnerseal.device.pairing.v1\x00" — used internally by sign_pairing_message
  PAIRING_COMMIT_LEN: usize = 32
  PAIRING_SAS_LEN: usize = 7
  PairingPayload
  PairingCommit
  PairingTranscript
  PairingSession
  build_pairing_payload(identity, capabilities) -> Result<PairingPayload>
  build_pairing_payload_with_nonce(identity, capabilities, nonce) -> Result<PairingPayload>
  validate_pairing_payload(payload) -> Result<()>
  compute_pairing_commit(payload) -> Result<PairingCommit>
  verify_pairing_commit(commit, payload) -> Result<()>
  compute_pairing_transcript(payload) -> Result<PairingTranscript>
  derive_bilateral_sas(nonce_self, nonce_peer, payload_self, payload_peer) -> Result<String>
  validate_trust_transition(from, to) -> Result<()>

transfer::
  SecretPayload
  TrustedSender
  TrustedSender::from_verified(identity: &DeviceIdentity) -> Result<TrustedSender>
  UntrustedTransferEnvelope
  UntrustedTransferEnvelope::validate_for_open(bytes: &[u8]) -> Result<UntrustedTransferEnvelope>
  TRANSFER_ENVELOPE_SIGNING_DOMAIN: &[u8]
    // b"meissnerseal.transfer.envelope.v1\x00" — used internally by create/open_envelope
  TransferProfileId
  TransferEnvelope
  SeenEnvelopeIds
  SeenEnvelopeIds::new() -> Self
  SeenEnvelopeIds::check_and_insert(id, expires_at) -> Result<(), TransferError>
  SeenEnvelopeIds::to_bytes() -> Vec<u8>
  SeenEnvelopeIds::from_bytes(bytes) -> Result<Self, TransferError>
  compute_transcript_hash(params: &TranscriptParams) -> [u8; 32]
  validate_envelope(envelope: &TransferEnvelope) -> Result<(), TransferError>
  create_envelope(params: CreateEnvelopeParams) -> Result<TransferEnvelope, TransferError>
  open_envelope(envelope: &TransferEnvelope, params: OpenEnvelopeParams, seen: &mut SeenEnvelopeIds) -> Result<SecretPayload, TransferError>

```

`CreateEnvelopeParams` supports two recipient-binding modes:
- identified mode: `recipient_device_id = Some(DeviceId)`,
  `anonymous_recipient_public_key = None`
- anonymous mode: `recipient_device_id = None`,
  `anonymous_recipient_public_key = Some(recipient_classical_public_key)`

Anonymous mode fails closed if the explicit public-key transcript binding is
absent.

---

## Planned (post-MVP-0)

These APIs are not part of the MVP-0 Stable contract. They will be locked
in future milestones as noted.

```
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
       Vault<Locked>::unlock performs a best-effort pre-read sweep of
       sibling orphan temp files whose names match exactly
       `{vault_stem}.{32-lowercase-hex}.msv.tmp`; non-matching siblings are
       left untouched and sweep failures do not change unlock semantics.
       Read-modify-write item mutations (`add`, `update`, `delete`) acquire a
       non-blocking advisory sidecar lock at `{vault_path}.lock` via the stable
       sibling path `vault_path.with_extension("msv.lock")`; contention returns
       `Err(CoreError::VaultLocked)` and never blocks indefinitely.

[G-02] item::with_item uses scoped access. PlainItemView lifetime is
       bounded to the closure. Owned plaintext is not returned.
       SEC-6 Phase 2 hardens this to `Result<()>` so callers cannot return
       `Vec<u8>`, `String`, `PlainItem`, or `SecretBytes`.

[G-04] transfer::open_envelope rejects:
       — expired envelopes (expires_at in the past)
       — replayed envelope_ids through SeenEnvelopeIds::check_and_insert
       — transcript hash mismatches
       — unknown or mismatched algorithm IDs
       — anonymous envelopes missing the recipient public-key transcript binding
       — untrusted sender identities at the API boundary through
         TrustedSender::from_verified
       SeenEnvelopeIds serializes accepted envelope IDs with expiry-aware
       eviction and fail-closed parsing.

[G-05] Vault parser rejects:
       — wrong magic bytes
       — unknown critical TLV tags
       — duplicate critical fields
       — missing `pqc_profile` header TLV
       — unsupported non-zero `pqc_profile` values with
         `CoreError::UnsupportedPqcProfile(observed_u16)`
       — truncated sections
       — trailing garbage

[G-06] All error paths return Err. No partial output on security failure.

[G-07] Device pairing SAS uses bilateral commit→reveal:
       each side commits to its nonce before reveal, commit verification fails
       closed on mismatch, and SAS derivation orders both identities by
       lower device_id first so both peers compute the same 7-character value.
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

[I-04] Anonymous transfer envelopes bind the recipient classical public key
       into the transcript at both create and open time. The create-side API
       requires this binding explicitly when `recipient_device_id` is absent.
```
