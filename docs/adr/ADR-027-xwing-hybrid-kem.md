<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-027: Adopt X-Wing as the Hybrid KEM Combiner

**Status:** Accepted
**Date:** 2026-06-09
**Related:** ADR-007 (SHA-256 transcript), ADR-012 (ML-KEM risk), ADR-023
             (libcrux ML-KEM backend), crypto_design.md §7, transfer_profile_v1.md §3–4

---

## Context

MeissnerSeal's hybrid key agreement (transfer, device pairing, sync key wrapping)
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

The hybrid layer is unimplemented (meissnerseal-pqc is a scaffold, scheduled MVP-2),
so there is **no migration cost** to fixing this now — the same posture ADR-023
took for the backend choice.

**X-Wing** (`draft-connolly-cfrg-xwing-kem`, in CFRG) is the proven hybrid of
**exactly X25519 + ML-KEM-768** — our exact parameters, zero mismatch. Its
security proof leverages ML-KEM-768's own ciphertext-binding to show that hashing
the ML-KEM ciphertext/public key into the combiner is unnecessary; binding the
X25519 ciphertext and recipient public key suffices.

---

## Decision

**Adopt X-Wing as the hybrid KEM for the transfer / pairing / sync key-wrapping
profiles, replacing the bespoke HKDF combiner. Planned construction; finalized at
MVP-2 against the conditions in point 5.**

**Why X-Wing and not the TLS `X25519MLKEM768` named group.** MeissnerSeal is not
designing a TLS named group; it is designing an *application-level* hybrid KEM for
transfer envelopes, device pairing and sync key wrapping. `X25519MLKEM768`
(draft-ietf-tls-ecdhe-mlkem) defines its combiner *inside the TLS 1.3 key
schedule* — outside TLS it is not a self-contained KEM, so reusing it would mean
re-specifying the KDF/transcript binding ourselves, i.e. back to a bespoke
construction. X-Wing (draft-connolly-cfrg-xwing-kem) is a standalone,
self-contained KEM purpose-built for exactly X25519 + ML-KEM-768, with a published
IND-CCA security bound, which is the right abstraction for our layer. The TLS named
group's stronger maturity signal (broad interop, Cloudflare/Chrome production
deployment) is real but is a *TLS-context* signal; it does not imply MeissnerSeal should
copy a TLS-internal combiner into its envelope format.

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
5. **Finalize-at-MVP-2, not a blind lock.** X-Wing is a CFRG *draft*, not a
   ratified RFC. The choice is committed in principle now (zero migration cost —
   the layer is empty) but the construction is frozen only at MVP-2 implementation,
   gated on: (a) X-Wing's RFC/CFRG progress, and (b) a verified libcrux X-Wing
   implementation. **Fallback:** if X-Wing stalls or its security analysis is
   weakened, use a generic "hash-everything" combiner (binding both ciphertexts and
   both shared secrets, not relying on ML-KEM-768's binding) per the
   Bindel-Brendel-Fischlin-Stebila hybrid-KEM analysis. Either way the bespoke
   transcript-as-salt combiner is retired.

---

## Alternatives Considered

**Keep the bespoke HKDF combiner.** Rejected: unproven custom construction;
incomplete KEM binding; against *no custom crypto*.

**Hand-patch §4 to add the recipient ML-KEM public key to the transcript.**
Rejected: still a bespoke combiner; X-Wing subsumes the binding question with a
proof, so patching is strictly inferior.

**Reuse the TLS `X25519MLKEM768` named group.** Rejected for the envelope layer:
its combiner is defined inside the TLS key schedule and is not a standalone KEM;
lifting it out means re-specifying the KDF binding ourselves (bespoke again). Its
production maturity is a TLS-context signal, not a reason to copy a TLS-internal
construct into an application envelope format.

**Generic hash-everything combiner now.** Not chosen as the primary, but retained
as the explicit fallback (Decision point 5): theoretically the most conservative
(no reliance on ML-KEM binding), but lacks a deployed *verified standalone*
implementation, so choosing it today means rolling our own — the very thing this
ADR removes.

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
