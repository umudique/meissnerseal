<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-036: ML-KEM-768 as the Selected Parameter Set

**Date:** 2026-06
**Status:** Accepted
**Supersedes:** —
**Related:** ADR-012 (ML-KEM risk), ADR-034 (RustCrypto backend), ADR-035 (UG combiner)

---

## Context

FIPS 203 defines three ML-KEM parameter sets. ADR-012 states that MeissnerSeal
uses ML-KEM-768 but does not record why 768 was chosen over 512 or 1024. This
ADR closes that gap.

### Parameter Set Comparison

| Parameter set | Security level | Classical equivalent | Ciphertext | Public key |
|---|---|---|---|---|
| ML-KEM-512 | NIST Level 1 | ~128 bit | 768 bytes | 800 bytes |
| **ML-KEM-768** | **NIST Level 3** | **~180 bit** | **1088 bytes** | **1184 bytes** |
| ML-KEM-1024 | NIST Level 5 | ~256 bit | 1568 bytes | 1568 bytes |

### Relevant constraints

1. **Hybrid composition.** MeissnerSeal pairs ML-KEM with X25519 (ADR-035 UG
   combiner). The hybrid is secure if either component is secure. X25519 already
   provides ~128-bit classical security. The PQC component's primary role is
   protecting against a future quantum adversary, not adding classical headroom
   beyond what X25519 already provides.

2. **Threat model scope.** MeissnerSeal is a local-first secrets vault for
   individual users and small teams. It is not a National Security System (NSS),
   a TLS library, or infrastructure for classified information. The adversary
   model (specs/security/threat_model.md) does not include nation-state quantum
   computer operators as an active, near-term operational threat.

3. **CNSA 2.0.** NSA's Commercial National Security Algorithm Suite 2.0 mandates
   ML-KEM-1024 for NSS. MeissnerSeal is not an NSS and CNSA 2.0 is not
   contractually binding. The project targets CNSA 2.0 alignment as a design
   goal, not strict compliance (see standards_conformance.md §2).

4. **Performance and wire size.** Transfer envelopes are stored locally and
   forwarded through the relay server. Ciphertext overhead per envelope:
   - ML-KEM-768: 1088 bytes
   - ML-KEM-1024: 1568 bytes (+480 bytes, +44%)
   The difference is not significant for a secrets vault, but there is no reason
   to accept the overhead without a corresponding security benefit.

---

## Decision

**Adopt ML-KEM-768 (NIST Level 3) as the ML-KEM parameter set for all
MeissnerSeal transfer and device operations.**

### Why not ML-KEM-512

Level 1 provides ~128-bit post-quantum security — the same as X25519's
classical security. In a hybrid scheme, if ML-KEM-512 were broken, the fallback
is X25519 at exactly the same security level. There is no defense-in-depth
margin. Level 3 adds a meaningful post-quantum security margin above the
classical baseline.

### Why not ML-KEM-1024

Level 5 targets ~256-bit post-quantum security. In a hybrid scheme, this
headroom exceeds what any known threat model requires for a personal secrets
vault within the project's threat model scope. The costs are:
- 44% larger ciphertext (1088 → 1568 bytes)
- Marginally slower key generation and encapsulation
- No current standard or regulator requires Level 5 for this use case

If MeissnerSeal is adopted in a regulated or NSS context in the future, this
ADR must be revisited. The crate boundary (meissnerseal-pqc) isolates the
parameter set to a single change point.

### Why ML-KEM-768

- NIST's recommended parameter set for general-purpose applications
- Provides ~180-bit post-quantum security, a meaningful margin above the
  ~128-bit classical baseline from X25519
- Accepted in all relevant standards bodies (ETSI, BSI, ANSSI) as the
  primary recommendation for non-classified contexts
- Ciphertext and public key sizes are manageable for local transfer envelopes

---

## Consequences

- All protocol identifiers, test vectors, spec files, and CONTRACT.md entries
  that reference ML-KEM-768 are confirmed correct under this decision.
- If MeissnerSeal is adopted for NSS or regulated use cases, a migration to
  ML-KEM-1024 requires: new profile ID, new test vectors, new ADR superseding
  this one. The meissnerseal-pqc crate boundary makes this a contained change.
- This ADR must be reviewed if NIST or a relevant authority downgrades the
  security recommendation for ML-KEM-768.
