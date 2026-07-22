<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# MeissnerSeal Pairing Protocol v1

**Protocol version:** `0x0001`  
**Status:** Specification  
**Related:** `transfer_profile_v1.md §6`, `crypto_design.md`, `docs/security/finding_register.yaml F-271`

---

## 1. Message Sequence

Pairing v1 is a bilateral out-of-band protocol. Both peers must exchange the
same fields in the same order:

1. `identity_A` → `identity_B`
2. `identity_B` → `identity_A`
3. `commit_A` → `identity_B`
4. `commit_B` → `identity_A`
5. `nonce_A`  → `identity_B`
6. `nonce_B`  → `identity_A`
7. each side verifies the received commitment against the revealed nonce
8. each side derives the same Short Authentication String (SAS)
9. users compare the SAS over an independent out-of-band channel
10. trust state may advance only after explicit user confirmation

The pairing flow must abort immediately if either commitment verification fails.
No trust root may be written before successful SAS confirmation.

---

## 2. Commitment Derivation

Each peer generates a fresh 32-byte random pairing nonce:

```text
nonce_A : [u8; 32]
nonce_B : [u8; 32]
```

Each peer computes a 32-byte commitment before revealing its nonce:

```text
commit_A = HKDF-SHA256-Extract(
  salt = b"meissnerseal.sas.commit.v1",
  ikm  = nonce_A || identity_bytes_A
)

commit_B = HKDF-SHA256-Extract(
  salt = b"meissnerseal.sas.commit.v1",
  ikm  = nonce_B || identity_bytes_B
)
```

The commitment output is exactly 32 bytes.

After both commitments are exchanged, each peer reveals its nonce. The receiver
must recompute the commitment from the revealed nonce and the already-exchanged
identity. Any mismatch must reject the pairing session.

Security invariant: commitment binding prevents a network attacker from waiting
to observe the peer nonce and then choosing an adaptive nonce that forces a
specific SAS value.

---

## 3. Canonical Identity Encoding

`identity_bytes` is the canonical byte encoding of the pairing identity fields,
in this exact order, excluding the pairing nonce:

```text
identity_bytes =
    protocol_version            : u16le
 || device_id                   : [u8; 16]
 || display_name_len            : u32le
 || display_name                : [u8; display_name_len]
 || classical_public_key_fp     : [u8; 32]
 || pqc_public_key_fp           : [u8; 32]
 || signing_public_key_fp       : [u8; 32]
 || capabilities                : u32le
```

Rules:

- `protocol_version` must be `0x0001`.
- `device_id` is the canonical 128-bit device identifier.
- `display_name_len` is the exact UTF-8 byte length of `display_name`.
- `display_name` is encoded exactly as exchanged; no case-folding, trimming, or
  normalization is permitted.
- Each fingerprint field is the full 32-byte SHA-256 digest of the raw public
  key bytes for that key class.
- `capabilities` is the exact little-endian 32-bit capability bitmask.

No implementation-defined field ordering, padding, or length encoding is
permitted.

---

## 4. SAS Derivation

After both commitments are verified, both sides derive the same SAS seed using
canonical device ordering:

```text
if device_id_A < device_id_B:
    first_nonce    = nonce_A
    second_nonce   = nonce_B
    first_identity = identity_bytes_A
    second_identity= identity_bytes_B
else:
    first_nonce    = nonce_B
    second_nonce   = nonce_A
    first_identity = identity_bytes_B
    second_identity= identity_bytes_A
```

The bilateral SAS seed is:

```text
sas_seed = HKDF-SHA256-Extract(
  salt = b"meissnerseal.sas.derive.v1",
  ikm  = first_nonce || second_nonce || first_identity || second_identity
)[0..4]
```

The displayed SAS is the RFC 4648 base32 encoding of the 4-byte `sas_seed`,
truncated to the 7 output characters implied by 32 input bits and no padding:

```text
SAS = BASE32_RFC4648_NO_PADDING(sas_seed)   // exactly 7 chars
```

Display rules:

- Alphabet is `A-Z2-7`.
- Padding is forbidden.
- Output length is exactly 7 characters.

---

## 5. Security Requirements

Implementations must enforce all of the following:

- Pairing commitments must be exchanged before nonce reveal.
- Commitment verification must fail closed on any mismatch.
- SAS derivation must use canonical lower-`device_id` ordering.
- SAS comparison must occur over an out-of-band channel controlled by the user.
- Pairing confirmation must not be presented if commitment verification fails.
- Device identity or key material must not be persisted before user SAS confirmation.

This protocol does not permit a unilateral or advisory-only SAS prompt. A SAS
that is not guaranteed to match on both peers is not a valid authentication
signal and must not gate trust establishment.
