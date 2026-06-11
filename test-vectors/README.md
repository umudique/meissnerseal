# MeissnerSeal Test Vectors

All cryptographic test vectors must be independently cross-verified —
the reference implementation and at least one independent calculation
(SageMath or Python) must produce identical results.

---

## Vector File Format

```json
{
  "profile": "KDF_ARGON2ID_V1",
  "version": 1,
  "description": "Human-readable description of what is tested",
  "generated_by": "reference implementation or tool name",
  "cases": [
    {
      "id": "descriptive-case-id",
      "inputs": {},
      "expected": {},
      "notes": "optional notes on this case"
    }
  ]
}
```

---

## Required Vector Files

| File | Profile | MVP Phase |
|---|---|---|
| `vault_kdf_v1.json` | KDF_ARGON2ID_V1 | MVP-0 |
| `vault_format_v1.json` | SCHEMA_ARCANUM_RECORDS_V1 | MVP-0 |
| `transfer_hybrid_v1.json` | TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1 | MVP-2 |
| `sync_envelope_v1.json` | sync envelope AEAD | MVP-3 |
| `recovery_kit_v1.json` | QVRK_RECOVERY_SECRET_V1 | MVP-1 |

---

## Required Test Cases Per Vector File

### vault_kdf_v1.json

- Basic unlock: password + vault_id → master_unlock_key
- Different vault_id produces different key (domain separation)
- Known bad parameters rejected (m=0, t=0, wrong argon2_version)

### vault_format_v1.json

- Header TLV serialize → parse round-trip
- Record frame serialize → AEAD encrypt → parse → AEAD decrypt round-trip
- AAD construction: fixed 74-byte canonical output
- AAD mismatch → AEAD failure
- Unknown critical tag → parse rejection
- Truncated header → parse rejection

### transfer_hybrid_v1.json

- Full hybrid derivation: x_secret || pq_secret → transcript_hash → transfer_key
- Transcript hash construction over all required fields
- Wrong transcript_hash → reject before decryption
- Wrong algorithm ID in transcript → reject
- Expired envelope → reject

### recovery_kit_v1.json

- Bech32m encode: seed → arc1... string
- Bech32m decode: arc1... → seed + recovery_id + profile_id
- Checksum error → rejection
- Wrong HRP → rejection
- Recovery key derivation: seed + vault_id + recovery_id → recovery_wrap_key
