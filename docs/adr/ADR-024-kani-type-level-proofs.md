<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-024: Kani Harnesses Are Type-Level Constant Proofs (MVP-0)

**Status:** Accepted  
**Date:** 2026-06-08  
**Related:** ADR-015 (mathematical verification strategy), ADR-005 (formal
methods), backlog P3-5 (real bounded-execution proofs before Stable+)

---

## Context

ADR-015 mandates a `#[cfg(kani)]` proof harness for every security-critical
function. Those harnesses exist today across the crypto, core, and security
crates (`aead.rs`, `types.rs`, `kdf/argon2.rs`, `kdf/hkdf.rs`, `rng.rs`,
`vault/format.rs`, `keys/hierarchy.rs`, `secret_lifecycle.rs`).

Inspecting them shows that the majority assert **type-level or compile-time
constant invariants**, not full symbolic execution of the operation. Examples:

```rust
// aead.rs — tag length is a constant, not a symbolic execution of the cipher
kani::assert(TAG_LEN == 16, "authentication tag must always be 16 bytes");

// vault/format.rs — AAD width is encoded in the return type [u8; 74]
kani::assert(core::mem::size_of::<[u8; 74]>() == 74, "AAD must be 74 bytes");

// vault/format.rs — minimum-length guard is a constant
kani::assert(HEADER_MIN_LEN == 26, "minimum prefix must be 26 bytes");
```

The harness comments state the reason explicitly: feeding `kani::any()` through
the real AEAD cipher, the Argon2 memory-hard function, or a symbolic-length
heap allocation causes **state-space explosion** that Kani cannot discharge in
practical time. A subset of harnesses do exercise bounded properties over
symbolic inputs (e.g. `decrypt` rejecting a short ciphertext, fixed-length key
constructors over `kani::any::<[u8; N]>()`), but the cryptographic
transformations themselves are not symbolically executed.

Left undocumented, this invites two misreadings: that the harnesses prove more
than they do (a false assurance), or that they are trivially worthless (an
unjustified dismissal). Neither is correct, and the gap belongs in an ADR
rather than a recurring review finding.

---

## Decision

Record that, for MVP-0, the Kani harnesses are **type-level constant proofs**
by design, not bounded-execution proofs of the cryptographic operations.

What they prove today, and why it has value:

- Fixed-length invariants encoded in the type system (`Key<N>` lengths, the
  74-byte AAD width, the 16-byte tag, the 26-byte header minimum) hold for all
  constructions — these are exactly the invariants whose violation would be a
  Critical security defect, and they are proven for the whole input domain
  because the domain is the type.
- Length-guard rejection paths (short ciphertext, short header) are proven over
  symbolic inputs where the bounded state space permits it.

What they explicitly do **not** prove today: the input/output correctness of
the AEAD seal/open, the KDF derivation chain, or the parser over symbolic
byte sequences. Those are covered at MVP-0 by the cross-verified test vectors
(`test-vectors/`, finding A2 drift guard) and the negative-fixture suite — not
by Kani.

Real bounded-execution proofs that symbolically execute these operations are
tracked as **backlog P3-5** ("Kani harnesses → real bounded-execution proofs")
and are required **before the Stable+ phase**, consistent with the progressive
escalation in ADR-015.

---

## Alternatives Considered

**Force full symbolic execution now (remove the constant-only harnesses):**  
Rejected. Symbolically executing XChaCha20-Poly1305, Argon2id, or a
symbolic-length parser blows up Kani's state space and yields no result in
practical CI time. A harness that never terminates is worse than a precise
constant proof plus a cross-verified vector.

**Delete the constant-level harnesses as "trivial":**  
Rejected. The fixed-length invariants they prove are precisely the ones whose
violation is Critical (nonce/tag/key/AAD width). Proving them for the entire
type domain at zero CI cost is genuine assurance, not noise.

**Leave the distinction implicit in code comments only:**  
Rejected. The harness comments already explain it case-by-case, but the
project-level rationale (why this is acceptable at MVP-0 and when it must
escalate) is an architectural decision and belongs in an ADR per ADR-015 /
the governance model.

---

## Consequences

- The Kani harnesses remain as type-level constant proofs through MVP-0; this
  is a documented, deliberate scope, not a coverage defect.
- Cryptographic input/output correctness at MVP-0 rests on the cross-verified
  test vectors and the CI drift guard (finding A2), not on Kani.
- Promotion to the Stable+ phase is gated on completing backlog P3-5: replacing
  the constant proofs with real bounded-execution proofs where the state space
  is tractable, and documenting any operation that remains out of Kani's reach.
- Any new security-critical function still ships a `#[cfg(kani)]` harness per
  ADR-015; this ADR clarifies what that harness is expected to prove at the
  current phase, not whether one is required.
