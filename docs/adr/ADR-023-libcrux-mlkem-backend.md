<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-023: Verified ML-KEM Backend (libcrux) for the PQC Layer

**Status:** Accepted
**Date:** 2026-06-08
**Related:** ADR-011 (RustCrypto ecosystem), ADR-012 (ML-KEM risk), ADR-015
             (mathematical verification), ADR-020 (dependency gate)

---

## Context

The post-quantum layer (`meissnerseal-pqc`) is currently unimplemented — the crate is
a scaffold (`mlkem`, `mldsa`, `hybrid`, `backend` are empty module stubs) and is
scheduled for MVP-2. No ML-KEM dependency has been added yet.

This is decisive. ADR-012 assumed the implementation backend would be the
RustCrypto `ml-kem` crate and recorded its residual risk:

- `ml-kem` crate **security audit: High** — no independent audit.
- **Side-channel resistance: High** — constant-time claimed, not formally verified.

ADR-012 §4 explicitly anticipated a future library swap confined to `meissnerseal-pqc`,
and §5 reserved formal verification for the *protocol* (symbolic level), not the
*implementation*. Because the layer is still empty, there is **no migration debt**:
we can choose the backend for the first implementation rather than swapping later.

In parallel, the formally-verified crypto ecosystem (Cryspen libcrux, hax→F*
lineage) has matured into normal, pure-Rust crates published on crates.io
(`libcrux-ml-kem`, `libcrux-ml-dsa`). This changes the trade-off that ADR-012 was
written against.

ADR-005 / ADR-015 reject *writing our own* formal proofs of MeissnerSeal as
disproportionate. This ADR is the complementary move: **consume** a verified
artifact rather than produce one.

---

## Decision

**Adopt `libcrux-ml-kem` (Cryspen) as the ML-KEM-768 backend for `meissnerseal-pqc`,
implemented directly at MVP-2. The RustCrypto `ml-kem` crate is not introduced.**

Scope and constraints:

1. **Verified core only.** Only the proven-core crates are in scope:
   `libcrux-ml-kem`, and (when the signature path is built) `libcrux-ml-dsa`.
   The broader libcrux peripheral ecosystem (hpke-rs, libcrux-psq, classical
   ECDSA/Ed25519 paths) is **explicitly out of scope** — see Risk note below.

2. **What the proof buys us.** For the ML-KEM core, libcrux's hax→F* verification
   establishes, against the FIPS 203 specification:
   - functional correctness,
   - panic-freedom (no `unwrap`/index-panic in the verified core),
   - secret-independence (constant-time) — the property ADR-012 could only
     *assume* for the `ml-kem` crate.
   This downgrades the two **High** rows of the ADR-012 risk table
   (audit gap, side-channel) toward **Low/Medium**.

3. **What the proof does NOT buy us.** Verification covers an abstract Rust model,
   not the compiler, intrinsics, or hardware, and it does **not** cover our usage
   contract. The `meissnerseal-pqc` wrapper (encapsulation/decapsulation, hybrid KDF
   combination, AAD/transcript binding, fail-closed error handling, Zeroize of
   transient secrets) remains **our** responsibility and must be validated by
   KAT test-vectors and Kani harnesses (ADR-015) exactly as classical primitives
   are.

4. **Hybrid is retained.** ADR-012's hybrid composition (X25519 + ML-KEM; secure
   if either component is secure) and the X25519-only fallback clause are
   unchanged. A verified ML-KEM backend strengthens, but does not replace, hybrid.

5. **Dependency gate.** Adding `libcrux-ml-kem` is a dependency change and a
   HUMAN-approved action (ADR-020). This ADR records the approval-in-principle of
   the *choice*; the actual `Cargo.toml` addition happens at MVP-2 implementation
   time, pinned in `Cargo.lock`, with `cargo vet` / supply-chain review applied
   as for any dependency, and must not regress SLSA/reproducibility posture
   (pure-Rust extracted code — no C toolchain required).

6. **License.** `libcrux-ml-kem` is dual-licensed `Apache-2.0 OR MIT` — permissive,
   commercial-use compatible, and consistent with the RustCrypto licensing already
   in the tree. Apache-2.0 additionally provides an explicit patent grant.

---

## Alternatives Considered

**RustCrypto `ml-kem` (the ADR-012 baseline):**
Rejected as the backend. Unaudited and not formally verified; carries the two
High risks ADR-012 documented. Since the PQC layer is empty, choosing it now would
incur exactly the migration cost ADR-012 §4 tried to defer, for no benefit over
starting on the verified crate.

**Write our own F*/formal proofs of MeissnerSeal's PQC code:**
Rejected — consistent with ADR-005 / ADR-015. Disproportionate for a
single-developer project; the value is in consuming verified artifacts, not
producing proofs of glue code.

**Adopt the full libcrux ecosystem (hpke-rs, psq, classical signatures):**
Rejected. Independent review (Symbolic Software, 2026-02) found concrete defects
in libcrux *peripheral* components — e.g. ECDSA low-S malleability, Ed25519
double-clamping, an AES-GCM `.unwrap()` panic, and hpke-rs nonce-overflow /
missing X25519 zero-check. None are in the ML-KEM core, but they show that the
"verified" label does not extend uniformly across the ecosystem. We therefore
take only the proven core and keep our classical primitives on RustCrypto
(ADR-011).

---

## Consequences

- ADR-012's risk table is revised at MVP-2: the audit-gap and side-channel rows
  move from High toward Low/Medium once libcrux-ml-kem is integrated. ADR-012
  should be cross-noted to point here.
- `meissnerseal-pqc/CONTRACT.md` must document: verified backend, the precise
  verification scope (core only), and that the usage-contract wrapper is validated
  by our own KAT + Kani, not by libcrux's proofs.
- The `dependency_risk_register.md` entry shifts from "unaudited ml-kem crate" to
  "verified libcrux-ml-kem; track Cryspen advisories and verification-scope notes."
- MVP-2 implementation starts directly on libcrux; no `ml-kem` crate is ever added,
  so there is no swap and no dual-backend period.
- This ADR must be revisited if libcrux's ML-KEM verification scope changes, if a
  Cryspen advisory affects the core, or if NIST/FIPS 203 guidance is updated.
