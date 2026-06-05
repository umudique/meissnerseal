# ADR-015: Mathematical Verification Strategy

**Date:** 2026-06
**Status:** Accepted

## Context

Arcanum stores secrets that are difficult or impossible to rotate.
A bug in the cryptographic layer can cause permanent, unrecoverable data loss.
The development team has no embedded security engineer reviewing every line.
AI agents write implementation code.

Mathematical verification reduces reliance on human review by encoding
correctness properties as machine-checkable artifacts.

The question is not whether to use formal methods, but which level is
appropriate at which phase.

## Decision

Adopt a four-level mathematical verification strategy, applied progressively.

### Level 1 — Const Generics (MVP-0, mandatory, free)

Use `Key<const N: usize>` for all fixed-length cryptographic values.
The length is encoded in the type and verified at compile time.
Zero runtime cost. No tooling required beyond the Rust compiler.

```rust
pub type AeadKey        = Key<32>;
pub type XChaCha20Nonce = Key<24>;
pub type VaultId        = Key<16>;
```

Enforces: nonce is always 24 bytes, key is always 32 bytes — as a
mathematical fact verified by the compiler, not a runtime assertion.

### Level 2 — Kani (MVP-0 harness skeletons, Beta full proofs)

Kani is a bounded model checker for Rust. It converts Rust code to
SMT formulas and proves properties against a Z3 solver.

Harness skeletons are written alongside implementation code at MVP-0.
Full proofs are completed as functions are implemented.

```rust
#[cfg(kani)]
#[kani::proof]
fn verify_aad_length() {
    let vault_id: [u8; 16]   = kani::any();
    let record_id: [u8; 16]  = kani::any();
    let revision_id: [u8; 16] = kani::any();
    let aad = build_aad_v1(vault_id, 1, 1, 1, 1, 0, record_id, revision_id, 1);
    kani::assert(aad.len() == 74, "AAD must always be 74 bytes");
}
```

### Level 3 — Prusti (Beta, deductive verification)

Prusti is a deductive verifier built on the Viper infrastructure.
It verifies Hoare triples: preconditions, postconditions, invariants.

```rust
use prusti_contracts::*;

#[requires(key.len() == 32)]
#[requires(nonce.len() == 24)]
#[ensures(result.len() == plaintext.len() + 16)]
fn xchacha20_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // ...
}
```

Targets: key derivation chain, TLV parser bounds, AAD construction.

### Level 4 — Creusot / Why3 / Coq (Research)

Creusot compiles Rust to Why3. Full deductive proofs via SMT solvers
or interactive theorem provers. Reserved for single critical functions
where lower-level verification is insufficient.

## Rationale

| Level | Phase | Cost | What it proves |
|---|---|---|---|
| Const generics | MVP-0 | Free | Length invariants at compile time |
| Kani | MVP-0+ | Low | Bounded properties, no overflow, no panic |
| Prusti | Beta | Medium | Hoare triples, postconditions |
| Creusot | Research | High | Full deductive proofs |

Mathematical verification augments, never replaces:
test vectors, Miri, fuzzing, and external security audit.

## Consequences

- `arcanum-crypto` introduces `Key<const N: usize>` as the canonical
  fixed-length secret type
- Kani harnesses written alongside implementation code (not after)
- `cargo kani` added to CI thorough pipeline (Beta+)
- Prusti added as optional annotation crate; used at Beta
- `#[cfg(kani)]` and `#[cfg(prusti)]` gate all proof code
- No proof code compiled into production binary
