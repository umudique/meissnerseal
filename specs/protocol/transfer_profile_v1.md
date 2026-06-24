<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# MeissnerSeal Transfer Profile v1

**Profile ID:** `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1`
**Status:** Specification — MVP-2
**Formal model:** `specs/formal/transfer_protocol.pv` (ProVerif — MVP-2)
**Fuzz target:** `fuzz/fuzz_targets/transfer_envelope.rs`
**Test vectors:** `test-vectors/transfer_hybrid_v1.json`

---

## 1. Profile Summary

| Component | Value |
|---|---|
| Classical KEM | X25519 (ephemeral sender, static recipient) |
| PQC KEM | ML-KEM-768 |
| Transcript hash | SHA-256 (32 bytes) |
| HKDF | HKDF-SHA256 |
| AEAD | XChaCha20-Poly1305 (default) |
| Context string | `"meissnerseal-transfer-v1"` |

SHA-384 and 48-byte transcripts are reserved for a future profile
(`TRANSFER_HYBRID_X25519_MLKEM1024_SHA384_V2`). They must not be mixed into v1.

---

## 2. Transfer Envelope Struct

```rust
pub struct TransferEnvelope {
    pub version: u16,
    pub transfer_profile: TransferProfileId,
    pub envelope_id: EnvelopeId,          // 128-bit random
    pub sender_device_id: DeviceId,
    pub recipient_device_id: Option<DeviceId>,
    pub classical_ephemeral_public_key: X25519PublicKey,
    pub pqc_ciphertext: MlKemCiphertext,
    pub transcript_hash: [u8; 32],        // SHA-256
    pub encrypted_payload: Vec<u8>,
    pub nonce: Nonce,                     // 192-bit for XChaCha20
    pub expires_at: Option<Timestamp>,
}
```

---

## 3. Hybrid Key Derivation

> **NOTE — Superseded by ADR-035 (UG hash-everything combiner, accepted 2026-06-17).**
> ADR-027 (X-Wing) was accepted then superseded by ADR-035, which adopted the
> UG combiner: IKM = ss_ML_KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ ct_ML_KEM,
> HKDF-SHA256-Extract with transcript_hash as salt, label "meissnerseal-transfer-v1".
> The legacy bespoke combiner below is retained for historical context only.
> ADR-035 and `crates/meissnerseal-pqc/src/hybrid.rs` are authoritative.

```
x_secret  = X25519(sender_ephemeral_private, recipient_static_public)
pq_secret = ML-KEM-768.Decapsulate(recipient_mlkem_private, pq_ciphertext)

hybrid_secret = HKDF-SHA256-Extract(
  salt = transcript_hash_sha256,
  ikm  = x_secret || pq_secret
)

transfer_key = HKDF-SHA256-Expand(
  prk    = hybrid_secret,
  info   = "meissnerseal-transfer-v1",
  length = 32
)
```

---

## 4. Transcript Hash Construction

The transcript hash binds all protocol parameters to prevent downgrade attacks:

```
transcript_input =
    "meissnerseal-transfer-transcript-v1"
 || transfer_profile_id : u16le
 || sender_device_id[16]
 || sender_classical_ephemeral_public_key[32]
 || recipient_device_id[16]   (or recipient_public_key[32] if anonymous)
 || pqc_ciphertext_len : u32le
 || pqc_ciphertext
 || classical_algorithm_id : u16le    (X25519 = 0x0001)
 || pqc_algorithm_id : u16le          (ML-KEM-768 = 0x0001)
 || envelope_id[16]
 || expires_at : i64le (0 if none)

transcript_hash = SHA256(transcript_input)
```

Any mismatch between computed and stored transcript_hash must reject
the transfer **before** any decryption attempt.

---

## 5. Downgrade Resistance Requirements

The protocol must reject:
- Unknown or mismatched transfer_profile_id
- Classical algorithm identifier not matching the profile
- PQC algorithm identifier not matching the profile
- transcript_hash length not matching the profile (32 bytes for v1)
- Missing PQC ciphertext in a hybrid-required profile
- Expired envelope (expires_at in the past)
- Replay of a previously accepted envelope_id

---

## 6. Device Pairing and Verification Chain

### Trust States

```rust
pub enum DeviceTrustState {
    Untrusted,
    PendingInbound,
    PendingOutbound,
    Verified,
    Approved,
    Approved,
    Revoked,
    Expired,
}
```

### Device Identity

```rust
pub struct DeviceIdentity {
    pub device_id: DeviceId,
    pub display_name: String,
    pub classical_public_key: X25519PublicKey,
    pub pqc_public_key: MlKemPublicKey,
    pub signing_public_key: Option<Ed25519PublicKey>,
    pub created_at: Timestamp,
    pub trust_state: DeviceTrustState,
}
```

**Invariant:** Any `DeviceIdentity` with `trust_state` of `Verified` or `Approved`
and `signing_public_key == None` must be rejected by validation before
reaching sync or transfer logic.

### Pairing Flow

1. QR/manual pairing payload includes:
   - protocol version, device_id, display_name
   - SHA256 fingerprints of: classical_public_key, pqc_public_key, signing_public_key
   - capabilities list, random pairing nonce
2. Pairing transcript is signed by the device signing key before approval
3. Approving device displays short authentication string for out-of-band verification
4. Remote pairing without OOB check is labeled as TOFU (weaker)
5. Device approval emits a signed device-trust event synced to all approved devices

### Revocation

- Revocation emits a signed revocation event
- Revoked devices cannot receive future sync-key wrapping
- Revocation triggers rotation of device-scoped sync keys
- **Limitation:** Revocation cannot erase secrets the device already decrypted — document this

---

## 7. Relay Server Trust Boundary

The relay server is an **untrusted availability component**. It may store and forward
encrypted envelopes but has no access to plaintext or keys.

| Data | Relay Visibility |
|---|---|
| Transfer ID | Opaque random 128-bit identifier |
| Upload/download time | Visible; documented limitation |
| Payload size | Visible; optional padding is a future claim |
| Sender account/IP | Minimized in logs; visible operationally |
| Recipient identity | Must be inside encrypted payload where practical |
| Envelope plaintext | Never visible |

### Relay Requirements

- Uploads: authenticated account session or single-use upload capability token
- Downloads: high-entropy transfer code or authenticated session
- `expires_at` enforced server-side AND client-side
- Default TTL: 24 hours; shorter options for high-risk transfers
- Maximum payload size enforced before storage
- Rate limits: by account, IP, transfer ID, unauthenticated token class
- Expired envelopes: deleted by background job; rejected by API before deletion
- Relay logs: no secret names, plaintext metadata, unwrapped keys
- **Offline/direct transfer is a first-class flow** — QR, file, USB, any channel

---

## 8. Security Properties (ProVerif Targets)

The ProVerif model at `specs/formal/transfer_protocol.pv` must verify:
- Secrecy of transfer payload against passive and active network adversary
- Authentication: only the intended recipient can decrypt
- Replay protection: previously accepted envelope_id cannot be reused
- Downgrade resistance: attacker cannot negotiate a weaker profile
