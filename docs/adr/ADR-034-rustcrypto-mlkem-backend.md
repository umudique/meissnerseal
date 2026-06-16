<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-034: ML-KEM Backend Revision — RustCrypto ml-kem

**Status:** Accepted
**Date:** 2026-06-16
**Supersedes:** ADR-023 (Verified ML-KEM Backend — libcrux)
**Related:** ADR-011 (RustCrypto ecosystem), ADR-012 (ML-KEM risk), ADR-015
             (mathematical verification), ADR-023, ADR-027 (X-Wing hybrid KEM),
             ADR-028 (signature crypto-agility)

---

## Context

ADR-023 selected `libcrux-ml-kem` (Cryspen) as the ML-KEM-768 backend for
`meissnerseal-pqc`, citing hax→F* formal verification as the decisive advantage
over the RustCrypto `ml-kem` crate. The PQC layer remains unimplemented — no
dependency has been added and no migration debt exists. This absence of
implementation debt makes it practical to reconsider before MVP-2 begins.

Three developments since ADR-023 change the balance of the decision:

**1. The November 2025 platform-dependent output bug.**
libcrux-ml-dsa v0.0.3 produced different outputs depending on the execution
environment — the same seed generated different public keys and signatures on
Alpine Linux / ARM64 versus macOS Apple Silicon. The root cause was an unverified
fallback implementation for the `vxarq_u64` intrinsic in the SHA-3 path. Because
both ML-DSA and ML-KEM rely on SHA-3 for hashing, this class of bug is not
exclusive to the DSA path. ADR-023 §3 (Decision) already acknowledged that
formal verification covers an abstract Rust model and "does not cover the
compiler, intrinsics, or hardware" — this incident is a concrete realisation of
exactly that caveat.

**2. Cryspen's disclosure posture.**
The November 2025 bug was fixed without any public announcement or security
advisory from Cryspen. The only advisory that exists was filed by a third party
(Joe Birr-Pixton, ctz) in the RustSec database. Cryspen requested the advisory
target the internal `libcrux-intrinsics` crate rather than the user-facing
`libcrux-ml-kem` / `libcrux-ml-dsa` crates — technically accurate but
practically obscuring the user-visible impact. A cryptographic library that
patches silent failures in its core primitive without public disclosure is not
compatible with MeissnerSeal's transparency requirements.

**3. The Symbolic Software review series (February–April 2026).**
ADR-023 already cited this series correctly in its "Alternatives Considered"
section: defects were found in libcrux *peripheral* components (hpke-rs, ECDSA,
Ed25519, libcrux-psq), not in the ML-KEM core. The peripheral scope remains
excluded. However, the series raised a broader concern — that formal verification
of an abstract Rust model does not prevent the class of engineering defects
(specification non-compliance, integer overflow, incorrect clamping, error
discarded by an unverified wrapper) that careful code review and testing would
catch. The "verification theater" framing describes a structural gap between what
the hax→F* proof covers and what users reasonably understand "formally verified"
to mean.

None of these developments constitute a known vulnerability in the libcrux-ml-kem
core. The case for revision is not that libcrux-ml-kem is broken — it is that the
original justification was stronger on paper than in practice, and that the
disclosure culture introduces a trust deficit that is difficult to manage in a
security-critical project.

---

## Decision

**Adopt RustCrypto `ml-kem` as the ML-KEM-768 backend for `meissnerseal-pqc`.
`libcrux-ml-kem` is not introduced. ADR-023 is superseded.**

Rationale:

1. **Ecosystem consistency.** The entire MeissnerSeal cryptographic stack is
   already RustCrypto (ADR-011): `chacha20poly1305`, `sha2`, `hkdf`, `argon2`,
   `subtle`, `zeroize`. Introducing a second vendor for the PQC layer adds audit
   surface and coordination overhead. A single-vendor cryptographic stack is
   simpler to audit and to reason about.

2. **The verification scope gap was realised.** ADR-023 §3 explicitly stated
   that verification does not cover intrinsics or hardware. The November 2025
   incident occurred precisely in that unverified layer. The advantage of formal
   verification was always bounded by this gap; it has now been demonstrated
   concretely.

3. **Disclosure culture is not negotiable.** Silent patches to a cryptographic
   primitive — regardless of severity assessment — are incompatible with the
   transparency standards MeissnerSeal applies to its own development. A library
   whose maintainer actively minimises advisory visibility cannot be treated as a
   trusted dependency.

4. **Project-level verification at the usage boundary.** ADR-005 and ADR-015
   adopt a "consume verified artifacts" posture to avoid the disproportionate
   cost of writing proofs. With libcrux, that posture was contingent on the
   "verified" label carrying sufficient weight. With RustCrypto `ml-kem`, the
   equivalent posture is: wide deployment, active community review, FIPS 203
   compliance, constant-time discipline via `subtle`, and Kani harnesses at the
   `meissnerseal-pqc` API boundary (PQC-1 task). This is a more honest position
   — the verification scope is exactly what we can state and test ourselves,
   rather than inherited from a label with documented gaps.

5. **ADR-012 baseline restored.** RustCrypto `ml-kem` was ADR-012's baseline
   assumption. ADR-023 upgraded it; this ADR reverts to it. The two residual
   risks ADR-012 documented (audit gap, side-channel) remain, and must be
   carried explicitly in the dependency risk register. The hybrid composition
   (X25519 + ML-KEM, ADR-027) is unchanged — classical security holds
   independently of ML-KEM.

---

## Alternatives Considered

**Retain libcrux-ml-kem (ADR-023 decision):**
The ML-KEM core has no known vulnerability. Retaining it is defensible on
narrow technical grounds. Rejected because the disclosure posture is a
governance risk that cannot be resolved by scoping, and because the formal
verification advantage — already bounded by ADR-023's own §3 caveat — has been
concretely weakened by the November 2025 intrinsics incident.

**fips203 (IntegrityChain):**
Pure Rust, `#[forbid(unsafe_code)]`, dudect constant-time measurements, embedded
(Cortex-M4) test targets. More conservative engineering posture than either
libcrux or RustCrypto. Rejected for MVP-2: self-described as experimental ("USE
AT YOUR OWN RISK") in its own documentation; deployment too narrow for the
unknown-unknowns risk to be acceptable in a security-critical layer. May be
reconsidered in a future phase as the crate matures.

**pqcrypto-mlkem / pqcrypto-kyber:**
Unmaintained. PQClean (upstream C reference) archived; RUSTSEC-2026-0161 filed.
Rejected without further evaluation.

**liboqs Rust bindings:**
C FFI surface; Rust bindings provided as-is. Trail of Bits audited the C library
(liboqs, 2025) but not the Rust layer. Rejected — same reasoning as ADR-023.

---

## Consequences

- ADR-023 status changes to **Superseded by ADR-034**.
- ADR-012 risk table is not upgraded. The two High rows (audit gap, side-channel)
  remain at their original values. The risk register must reflect this accurately.
- `dependency_risk_register.md`: ML-KEM row updated to RustCrypto `ml-kem`; the
  "Selection Pending" block is removed; audit status documented honestly (no
  independent audit, FIPS 203 compliant, wide deployment, constant-time via
  `subtle`).
- `meissnerseal-pqc` Kani harnesses remain mandatory at the usage boundary
  (PQC-1 task scope). This is now the primary project-controlled verification
  mechanism for the PQC layer, not inherited verification from the backend.
- `meissnerseal-pqc/CONTRACT.md` must document: RustCrypto `ml-kem` backend,
  audit status, verification scope (Kani at usage boundary only), and that hybrid
  composition (ADR-027) provides the classical security floor.
- This ADR must be revisited if RustCrypto `ml-kem` receives an independent
  security audit, if a CVE is filed against it, or if `fips203` matures to a
  production-ready posture.
