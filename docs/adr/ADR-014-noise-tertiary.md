<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-014: Continuous Noise Floor as Tertiary Defense Layer

**Date:** 2025-06
**Status:** Accepted

## Context

Side-channel attacks exploit information leaked through timing, power consumption,
electromagnetic emission, or cache behavior. One proposed mitigation is adding
artificial noise (dummy operations, random delays) to obscure the signal.

## The Limits of Noise

Statistical signal processing removes noise given enough measurements.
With N measurements, signal-to-noise ratio improves by √N:

- 1,000 measurements: ~32× noise reduction
- 10,000 measurements: ~100× noise reduction
- 100,000 measurements: ~316× noise reduction

Noise raises the cost of an attack. It does not make an attack impossible.
Noise alone is not a mathematical security guarantee.

Additionally, continuous dummy operations can interfere with constant-time
guarantees if they create observable timing differences between "real operation"
and "noise operation" patterns.

## Decision

Side-channel protection is organized in three layers:

**Layer 1 — Primary (mandatory for cryptographic crates):**
Constant-time implementation using `subtle` crate.
No secret-dependent branches or memory accesses.
Verified with Miri (UB detection) and dudect (timing leakage, Beta).

**Layer 2 — Secondary (where applicable):**
Algorithmic masking: randomize inputs before cryptographic operations.
Point blinding for ECC. Boolean masking where applicable.
Provides defense even against attackers with many measurements.

**Layer 3 — Tertiary (defense-in-depth, after Layers 1 and 2):**
Noise and dummy operations may be added as a supplementary layer.
Must be documented with explicit limitations.
Must not be presented as a security guarantee.
Must not interfere with Layer 1 constant-time properties.

## Consequences

- `specs/security/security_assurance.md` documents the three-layer hierarchy
- Any implementation of noise/dummy operations must be labeled tertiary
- Product communications must not describe noise as a primary defense
- Timing side-channel claims are scoped to Layer 1 (constant-time) only
