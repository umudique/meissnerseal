<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-012: ML-KEM Risk Acknowledgment and Mitigation Plan

**Date:** 2025-06
**Status:** Accepted

> **Update 2026-06-16.** ADR-023 (libcrux-ml-kem) was superseded by **ADR-034**,
> which adopts RustCrypto `ml-kem` as the backend. ADR-023 was never implemented.
> The risk rows below remain valid for the RustCrypto backend. The hybrid
> composition and the X25519-only fallback clause remain in force.

## Context

MeissnerSeal's hybrid transfer protocol requires ML-KEM-768 (NIST FIPS 203).
The rationale for choosing ML-KEM-768 over ML-KEM-512 and ML-KEM-1024 is in
**ADR-036**.
Unlike the classical RustCrypto crates (ADR-011), the ML-KEM Rust ecosystem
is newer and has less accumulated audit history.

## Risk Assessment

| Risk | Severity | Current Status |
|---|---|---|
| FIPS 203 specification correctness | Low | Standard finalized and published |
| RustCrypto `ml-kem` crate correctness | Medium | Test-vector verified against FIPS 203 |
| RustCrypto `ml-kem` crate security audit | High | No independent security audit as of 2025-06 |
| Side-channel resistance of implementation | High | Constant-time claims present; not formally verified |
| Long-term NIST confidence | Low | ML-KEM selected after multi-year process |

## Decision

Accept ML-KEM risk with the following active mitigations:

1. **Hybrid composition** — X25519 provides classical security even if ML-KEM fails.
   The system is secure if either component is secure.

2. **Audit tracking** — The `dependency_risk_register.md` tracks the audit status
   of the ML-KEM crate. Any published audit is reviewed within 30 days.

3. **Crate pinning** — The ML-KEM crate version is pinned in Cargo.lock.
   Minor version bumps require manual review before acceptance.

4. **Isolation** — ML-KEM operations are confined to `meissnerseal-pqc`.
   A future library swap requires changes only in that crate.

5. **Formal verification scope** — The ProVerif model (MVP-2) verifies
   the hybrid protocol properties at the symbolic level, independent of
   the ML-KEM implementation.

6. **Fallback clause** — If a critical vulnerability is found in the ML-KEM
   crate before a patched version is available, the system can operate
   in X25519-only mode pending a fix, with a documented security downgrade notice.

## Consequences

- ML-KEM crate must be documented in `dependency_risk_register.md` with
  audit status and version before MVP-2 ships
- CONTRACT.md for `meissnerseal-pqc` must document the audit gap
- `cargo vet` review must be applied to the ML-KEM crate before beta
- This ADR must be reviewed and updated when an independent audit is published
