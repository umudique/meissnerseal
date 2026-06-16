<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-028: Signature Crypto-Agility and Post-Quantum Signature Posture

**Status:** Accepted
**Date:** 2026-06-09
**Related:** ADR-012 (ML-KEM risk / hybrid logic), ADR-034 (RustCrypto backend),
             ADR-035 (UG combiner), transfer_profile_v1.md §6, crypto_design.md §8

---

## Context

Device identity, pairing transcripts and revocation events are authenticated with
an **Ed25519** signing key. In `DeviceIdentity` the type is hardcoded:

```rust
pub signing_public_key: Option<Ed25519PublicKey>,
```

For a product positioned for the post-quantum era this raises two questions:
why is the signature classical, and can it migrate?

**Why classical is correct for now.** Post-quantum urgency is driven by
*harvest-now-decrypt-later* (HNDL), which threatens **confidentiality**, not
**authenticity**. A quantum adversary cannot forge a *past* signature
retroactively — the authentication decision was made and acted upon at signing
time. The migration deadline for signatures is "before a cryptographically
relevant quantum computer exists," not "now." This is why KEMs must go PQ
immediately (ADR-012/027) while signatures can follow — the same posture taken by
TLS, Signal, and the IETF.

**Why the current design is nonetheless deficient.** The key type is *pinned to
Ed25519*. Adding a PQ signature later would break the `DeviceIdentity` format —
there is no agility slot.

**Why not ML-DSA-only when we migrate.** The ML-DSA *algorithm* (FIPS 204) is
strong, but the *implementation* audit posture is weak across all available crates:
RustCrypto `ml-dsa` has no independent security audit as of 2026-06; the
alternative formally-verified backend (`libcrux-ml-dsa`) is excluded for governance
reasons (ADR-034 §2–3) and carries RUSTSEC-2026-0077 and RUSTSEC-2026-0126. The
dependency risk register has no ML-DSA entry yet. Because signatures have no HNDL
urgency, we can wait for that audit posture to mature rather than rush.

---

## Decision

1. **Keep Ed25519 for MVP signing.** Correct given the absence of HNDL urgency on
   authenticity.
2. **Open the agility slot now.** The device signing key becomes
   **algorithm-tagged** (an algorithm identifier + key bytes) rather than a bare
   `Ed25519PublicKey`, and the signature algorithm ID is carried in the
   *authenticated* content of pairing and revocation events (downgrade resistance
   for signatures, mirroring the KEM transcript binding). This change is made when
   device identity is implemented (MVP-2), but the decision is recorded now so the
   format is designed agile from the start.
3. **Fill the slot as a hybrid, not a replacement.** When PQ signatures are added,
   use **Ed25519 + ML-DSA hybrid** (valid if either holds), not ML-DSA alone — the
   classical floor guards against an immature ML-DSA *implementation* defect,
   exactly mirroring ADR-012's KEM-hybrid reasoning. Backend: RustCrypto `ml-dsa`
   (ADR-034 ecosystem), gated on its audit maturity at integration time.

---

## Alternatives Considered

**Replace Ed25519 with ML-DSA-only now.** Rejected: unnecessary (no HNDL on
signatures) and premature (immature ML-DSA implementation audit); discards the
classical floor.

**Keep Ed25519 hardcoded; revisit at MVP-2.** Rejected: opening the agility slot
is nearly free now and avoids a `DeviceIdentity` format break later.

**Hash-based signatures (SLH-DSA / SPHINCS+).** Noted but not selected for
pairing: most conservative (relies only on hash security) but signature sizes
(~7–30 KB) are impractical for QR/OOB pairing payloads. May reconsider for
low-frequency, high-assurance signing (e.g. release signing) separately.

---

## Consequences

- `DeviceIdentity` gains an algorithm-tagged signing key type when device identity
  is built (MVP-2); transfer_profile_v1.md §6 is updated accordingly.
- The dependency risk register must add an ML-DSA row and correct its stale
  pre-ADR-023 ML-KEM entry (it still names the RustCrypto `ml-kem` crate as TBD).
- Release-artifact signing (crypto_design.md §8 "Future") is a separate decision;
  this ADR covers device/pairing/revocation signatures only.
- Revisit when RustCrypto `ml-dsa` receives an independent security audit, or if
  an alternative ML-DSA implementation with stronger audit posture becomes available.
