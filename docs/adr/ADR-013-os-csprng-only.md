<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-013: OS CSPRNG as the Sole Source of Randomness

**Date:** 2025-06
**Status:** Accepted

## Context

Cryptographic randomness is foundational. A weak or backdoored RNG
defeats all cryptographic guarantees regardless of algorithm strength.
The Dual EC DRBG backdoor (published 2013) showed that standardized
deterministic RNGs can carry hidden trapdoors.

## Decision

MeissnerSeal must never implement a custom RNG. All randomness comes from
the OS CSPRNG through a single centralized module: `meissnerseal-crypto::rng`.

Implementation:
- `rand` crate with `getrandom` feature delegates to OS entropy
- `meissnerseal-crypto::rng` is the only module allowed to call random generation
- All other code requests randomness through this module's API
- Test modules may use seeded deterministic RNG for reproducibility,
  clearly marked `#[cfg(test)]` only

## Why This Eliminates the Dual EC DRBG Class of Backdoor

Dual EC DRBG required:
- A custom RNG implementation
- Elliptic curve constants that could have a hidden discrete log relationship
- Users who trust the constant selection

MeissnerSeal has:
- No custom RNG
- No custom elliptic curve constants
- HKDF info strings are ASCII text, derivable from documented inputs
- OS CSPRNG entropy sourced from kernel (Linux: getrandom, Windows: BCryptGenRandom,
  macOS: CCRandomGenerateBytes)

The OS may be compromised — this is documented in the threat model Out of Scope section.
The OS CSPRNG backdoor risk is transferred to the OS vendor and kernel, not MeissnerSeal.

## Consequences

- `meissnerseal-crypto::rng` is the sole randomness interface
- Callers cannot supply nonces to AEAD APIs in production builds
- Test code using deterministic RNG must be `#[cfg(test)]` gated
- `cargo geiger` monitors for unsafe code that might bypass this constraint
