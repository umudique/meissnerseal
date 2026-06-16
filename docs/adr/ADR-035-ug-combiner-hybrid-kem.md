<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-035: Hybrid KEM Combiner Revision — UG Hash-Everything Construction

**Status:** Accepted
**Date:** 2026-06-16
**Supersedes:** ADR-027 (X-Wing Hybrid KEM Combiner)
**Related:** ADR-007 (SHA-256 transcript), ADR-011 (RustCrypto ecosystem), ADR-012 (ML-KEM risk),
             ADR-027, ADR-034 (RustCrypto ML-KEM backend),
             crypto_design.md §7, transfer_profile_v1.md §3–4

---

## Context

ADR-027 selected X-Wing (`draft-connolly-cfrg-xwing-kem`) as the hybrid KEM combiner for transfer
envelopes, device pairing, and sync key wrapping. Its rationale was a published IND-CCA security
proof for X25519 + ML-KEM-768, an exact parameter match for MeissnerSeal, and CFRG sponsorship.

Two developments since ADR-027 change the balance:

**1. ADR-034 superseded ADR-023 (libcrux).**
ADR-027 §4 committed to "a verified libcrux X-Wing implementation as it matures" as the preferred
backend, falling back to manual composition otherwise. ADR-034 rejected libcrux entirely on
disclosure culture and intrinsics-layer grounds. No verified standalone X-Wing Rust implementation
exists outside libcrux. The primary backend path ADR-027 assumed is gone.

**2. The C2PRI dependency is unnecessary for MeissnerSeal.**
X-Wing's security proof omits the ML-KEM ciphertext (`ct_ML_KEM`) from the combiner hash,
relying instead on ML-KEM-768's Ciphertext Second-Preimage Resistance (C2PRI) — a property that
holds for ML-KEM-768 but is a stronger-than-standard assumption beyond IND-CCA2. For a
low-throughput application like MeissnerSeal (transfer envelopes, not TLS), hashing the full
`ct_ML_KEM` (~1 KB) adds no meaningful cost while eliminating the C2PRI assumption entirely.
There is no incentive to rely on a non-minimal assumption when the cost of avoiding it is zero.

---

## Decision

**Adopt the UG hash-everything combiner (`draft-irtf-cfrg-hybrid-kems`) as the hybrid KEM
construction for `meissnerseal-pqc`. ADR-027 (X-Wing) is superseded.**

The combiner input is:

```
hybrid_ss = HKDF-SHA256(
  salt  = transcript_hash,      // envelope-level downgrade binding (ADR-007)
  ikm   = ss_ML_KEM             // ML-KEM-768 shared secret
          || ss_X25519          // X25519 shared secret
          || ct_X25519          // X25519 ephemeral ciphertext
          || pk_X25519          // recipient X25519 static public key
          || ct_ML_KEM          // ML-KEM-768 ciphertext (~1 KB)
)
```

Design notes:

1. **`pk_ML_KEM` is bound at the protocol level, not in the combiner.** The sender encapsulates
   to `pk_ML_KEM` taken from an **authenticated `DeviceIdentity`** (fingerprints signed at
   pairing). Key confirmation via the DeviceIdentity path provides the necessary binding;
   including `pk_ML_KEM` in the combiner hash would be redundant given this structure. ADR-027
   §2 made the same architectural choice.

2. **ADR-007 is not superseded.** The `transcript_hash` (SHA-256, 32 bytes) continues to serve
   as the HKDF salt for envelope-level downgrade binding (profile ID, algorithm IDs, `envelope_id`,
   `expires_at`). The combiner's KDF and the transcript's role are distinct mechanisms.

3. **Profile name is unchanged.** `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1` describes the
   components (X25519, ML-KEM-768, SHA-256 KDF), not the internal combiner construction.

Rationale:

1. **No C2PRI assumption.** The UG combiner requires only standard IND-CCA2 security from both
   components. It makes no assumption beyond what X25519 and ML-KEM-768 already guarantee.
   Conservative assumptions are preferable when they cost nothing — this is a direct application
   of the same principle that drives hybrid KEM design itself.

2. **Implementable today over RustCrypto.** The construction is a straightforward composition of
   `ml-kem` (ADR-034) + `x25519-dalek` (ADR-011) + `hkdf` (already in the tree). No new
   dependency, no pre-release library, no wait for an external verified standalone implementation.

3. **Simpler construction, smaller audit surface.** The UG combiner is a KDF over concatenated
   inputs with a direct security argument. The implementation risk reduces to correctly specifying
   the binding inputs, which is verifiable by KAT test vectors.

4. **ADR-007 integration.** Using `transcript_hash` as the HKDF salt aligns with the existing
   project pattern. The UG combiner extends this naturally rather than introducing a separate
   combiner hash layer.

---

## Alternatives Considered

**Retain X-Wing (ADR-027).** Rejected: no verified standalone Rust implementation exists now
that libcrux is excluded (ADR-034). Composing X-Wing ourselves without a reference implementation
reintroduces a bespoke construction risk — exactly what ADR-027 was written to avoid. X-Wing's
C2PRI optimization is irrelevant at MeissnerSeal's throughput profile.

**Wait for a non-libcrux verified X-Wing implementation.** Rejected: indefinite schedule
dependency with no implementation horizon. The UG combiner is available today over existing
dependencies.

**Bespoke HKDF combiner (pre-ADR-027 construction).** Rejected: same reasons as ADR-027. The UG
combiner from `draft-irtf-cfrg-hybrid-kems` is the analysis-backed standardized form of
"hash everything." There is no reason to deviate from it.

---

## Consequences

- ADR-027 status changes to **Superseded by ADR-035**.
- `PQC-2` task: title updated to UG combiner; spec reference updated to this ADR.
- `XFER-1`, `XFER-2`, `FORMAL-2` spec references: `ADR-027` → `ADR-035`.
- `GATE-PQC` description updated to reflect UG combiner.
- `crypto_design.md §7` and `transfer_profile_v1.md §3–4` are revised at MVP-2 to specify the
  UG combiner construction; X-Wing text is removed.
- This ADR must be revisited if `draft-irtf-cfrg-hybrid-kems` is materially revised before
  publication, if a verified standalone X-Wing Rust implementation becomes available and makes
  the C2PRI-relying construction strategically valuable, or if MeissnerSeal adds a high-throughput
  path where `ct_ML_KEM` overhead becomes relevant.
