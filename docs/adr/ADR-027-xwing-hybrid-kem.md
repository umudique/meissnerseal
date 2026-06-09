# ADR-027: Adopt X-Wing as the Hybrid KEM Combiner

**Status:** Accepted
**Date:** 2026-06-09
**Related:** ADR-007 (SHA-256 transcript), ADR-012 (ML-KEM risk), ADR-023
             (libcrux ML-KEM backend), crypto_design.md §7, transfer_profile_v1.md §3–4

---

## Context

Arcanum's hybrid key agreement (transfer, device pairing, sync key wrapping)
combines a classical KEM (X25519) with a post-quantum KEM (ML-KEM-768) so the
result is secure if **either** component is secure. The current spec defines a
**bespoke combiner**:

```
hybrid_prk = HKDF-SHA256-Extract(salt = transcript_hash, ikm = x_secret || pq_secret)
```

Two problems:

1. **It is a custom protocol-level construction with no security proof.** A naive
   combiner is not automatically IND-CCA2 *robust*: neither DH nor ML-KEM is by
   itself "binding," so an adversary may craft distinct (ciphertext, public key)
   pairs yielding the same shared secret (the non-committing-KEM problem). The
   bespoke combiner is in tension with the project principle *no custom crypto*.
2. **The transcript does not bind the recipient ML-KEM encapsulation key.** §4
   binds the X25519 ephemeral, the ML-KEM ciphertext and the algorithm IDs, but
   not the recipient's ML-KEM public key.

The hybrid layer is unimplemented (arcanum-pqc is a scaffold, scheduled MVP-2),
so there is **no migration cost** to fixing this now — the same posture ADR-023
took for the backend choice.

**X-Wing** (`draft-connolly-cfrg-xwing-kem`, in CFRG) is the proven hybrid of
**exactly X25519 + ML-KEM-768** — our exact parameters, zero mismatch. Its
security proof leverages ML-KEM-768's own ciphertext-binding to show that hashing
the ML-KEM ciphertext/public key into the combiner is unnecessary; binding the
X25519 ciphertext and recipient public key suffices.

---

## Decision

**Adopt X-Wing as the combiner for the hybrid KEM in the transfer / pairing /
sync key-wrapping profiles, replacing the bespoke HKDF combiner. Implemented at
MVP-2.**

1. The bespoke combiner in crypto_design.md §7 and transfer_profile_v1.md §3 is
   superseded by X-Wing's construction.
2. **Problem (2) is resolved by construction, not by a transcript patch.** X-Wing
   binds the X25519 ciphertext + recipient public key and relies on ML-KEM-768's
   ciphertext-binding for the PQ side. The sender MUST encapsulate to ML-KEM /
   X25519 keys taken from an **authenticated `DeviceIdentity`** (fingerprints
   signed at pairing), which completes the identity-binding chain.
3. **ADR-007 is NOT superseded.** The envelope `transcript_hash` (SHA-256, 32
   bytes) continues to serve envelope-level downgrade binding (profile ID,
   algorithm IDs, envelope_id, expires_at). X-Wing's *internal* combiner hash
   (SHA3-256) is a distinct mechanism for a distinct job; the two hashes do not
   conflict.
4. Backend: prefer a verified X-Wing implementation as it matures in libcrux
   (consistent with ADR-023 "consume verified artifacts"); otherwise compose
   X-Wing over libcrux-ml-kem + a RustCrypto X25519 per ADR-011, validated by
   our own KAT vectors + Kani harnesses.

---

## Alternatives Considered

**Keep the bespoke HKDF combiner.** Rejected: unproven custom construction;
incomplete KEM binding; against *no custom crypto*.

**Hand-patch §4 to add the recipient ML-KEM public key to the transcript.**
Rejected: still a bespoke combiner; X-Wing subsumes the binding question with a
proof, so patching is strictly inferior.

**Defer the decision to MVP-2 implementation time.** Rejected: deciding now costs
nothing (layer empty) and prevents the design debt from being silently
re-derived later.

---

## Consequences

- crypto_design.md §7 and transfer_profile_v1.md §3–4 are revised at MVP-2 to
  specify X-Wing; the bespoke combiner text is removed.
- The future profile `TRANSFER_HYBRID_X25519_MLKEM1024_SHA384_V2` will need its
  own proven combiner (an X-Wing variant or successor), not a tweak of v1.
- This ADR must be revisited if X-Wing's draft changes materially before RFC, or
  if its security analysis is revised.
