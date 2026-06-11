<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# MeissnerSeal Standards Conformance

**Status:** Active reference — maintained alongside security_assurance.md
**Related:** [security_assurance.md](../../specs/security/security_assurance.md),
            [ADR-016](../adr/ADR-016-standards-conformance.md),
            [supply_chain.md](supply_chain.md)

---

## 1. Purpose

This document maps MeissnerSeal's design and practices to recognized security
standards. It serves two purposes:

1. **Internal discipline** — standards provide vocabulary and checklists that
   catch gaps a bespoke approach might miss.
2. **External credibility** — institutional and regulated-industry adopters
   can verify the project against standards they already know.

Standards alignment is a design target, not a marketing claim. Where alignment
is partial or future-targeted, that is stated explicitly.

---

## 2. CNSA 2.0 — NSA Commercial National Security Algorithm Suite

**Status:** Design target (post-quantum primitives already in architecture)
**Reference:** NSA CNSA 2.0 (2022), transition deadline 2030 for NSS

CNSA 2.0 mandates migration to post-quantum algorithms for National Security
Systems. MeissnerSeal's architecture was designed from the start to align with this
transition.

### Algorithm Mapping

| CNSA 2.0 Requirement | MeissnerSeal Primitive | Status |
|---|---|---|
| Key agreement (PQC) | ML-KEM-768 (`TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1`) | In architecture, MVP-2 |
| Key agreement (classical, hybrid) | X25519 (hybrid with ML-KEM-768) | In architecture, MVP-2 |
| Digital signatures | ML-DSA (device signing — future) | Noted, not yet scoped |
| Symmetric encryption | AES-256-GCM / XChaCha20-Poly1305 (256-bit key) | MVP-0 |
| Hash / KDF | SHA-256, HKDF-SHA-256, Argon2id | MVP-0 |

### Explicit Non-Alignment

- MeissnerSeal does not use P-384 or RSA-4096 as primary algorithms — these are
  CNSA 2.0 classical fallbacks, not targets for new designs.
- ML-DSA for device identity keys is noted but not scheduled before Beta.
- "CNSA 2.0 compliant" is not a product claim. The correct framing is:
  "CNSA 2.0-aligned post-quantum-ready design."

---

## 3. NIST SSDF — Secure Software Development Framework (SP 800-218)

**Status:** Practice mapping — enforced via AGENTS.md and security_engineering_protocol.md
**Reference:** NIST SP 800-218 v1.1 (2022)

SSDF defines four practice groups: Prepare the Organization (PO), Protect the
Software (PS), Produce Well-Secured Software (PW), Respond to Vulnerabilities (RV).

### Practice Mapping

| SSDF Practice | MeissnerSeal Control | Location |
|---|---|---|
| PO.1 — Security requirements | Threat model, security assurance matrix | `specs/security/` |
| PO.2 — Roles and tools | Agent roles, tool inventory | `AGENTS.md`, `security_engineering_protocol.md` §3 |
| PO.3 — Tool configuration | Pre-commit hooks, CI pipelines | `.githooks/pre-commit`, `.github/workflows/` |
| PO.4 — Security criteria | Phase gates, Release Security Gates | `security_assurance.md` §6, `AGENTS.md` §12 |
| PS.1 — Store code securely | Git repository, signed commits (Beta+) | `docs/ops/` |
| PS.2 — Protect branches | Protected main branch, PR gates | CI configuration |
| PS.3 — Archive releases | SBOM, signed releases (Beta+) | `security_assurance.md` §6 |
| PW.1 — Design best practices | ADRs, threat model, fail-closed rules | `docs/adr/`, `specs/security/` |
| PW.2 — Verify third-party | cargo audit, cargo deny (gates); cargo vet (informational, Beta gate) | `security_engineering_protocol.md` §3 Layer 2 |
| PW.4 — Reuse secure components | RustCrypto ecosystem (ADR-011) | `docs/adr/ADR-011-rustcrypto-ecosystem.md` |
| PW.5 — Check for vulnerabilities | cargo audit CVE scanning, geiger | Layer 2 tools |
| PW.6 — Test security | Property tests, fuzz targets, Kani, Miri | Layers 3–8 |
| PW.7 — Secure code review | Security Review Agent (evaluator role) | `AGENT_PROMPT_TEMPLATE.md` |
| PW.8 — Test for vulnerabilities | Fuzzing, ASan, side-channel review | Layers 5–7 |
| RV.1 — Identify vulnerabilities | cargo audit, responsible disclosure policy | `security_assurance.md` |
| RV.2 — Assess vulnerabilities | Security Review Agent scorecard | `AGENT_PROMPT_TEMPLATE.md` |
| RV.3 — Respond to vulnerabilities | Fix → re-verify → release gate | `docs/development/workflow.md` |

---

## 4. NIST SP 800-90B — Entropy Source Validation

**Status:** Delegated to OS — documented here per SP 800-90B transparency requirement
**Reference:** NIST SP 800-90B (2018)

MeissnerSeal uses OS CSPRNG exclusively (ADR-013). This delegates entropy source
responsibility to the operating system kernel, which is the correct model for
application software.

### Platform Entropy Sources

| Platform | Entropy Source | SP 800-90B Status |
|---|---|---|
| Linux | `getrandom(2)` / `/dev/urandom` (ChaCha20 DRBG after seeding) | Kernel-validated |
| macOS / iOS | `CCRandomGenerateBytes` → Secure Enclave entropy | OS-validated |
| Windows | `BCryptGenRandom` (Windows CNG) | FIPS 140-2 validated in OS |
| Android | `getrandom(2)` (Linux kernel) | Kernel-validated |

### MeissnerSeal's Responsibility Boundary

MeissnerSeal does not implement or modify the entropy source. The project's
obligation is:

1. Use only `OsRng` from the `rand_core` crate (which calls OS primitives).
2. Never seed from user-controlled, time-based, or deterministic sources.
3. Document the platform entropy surface in this file and in ADR-013.
4. Re-evaluate if a platform target adds an OS without a well-characterized
   entropy source.

---

## 5. TVLA / ISO 17825 — Side-Channel Leakage Assessment

**Status:** Beta target — methodology binding established now
**Reference:** ISO 17825:2016; TVLA (Welch's t-test, Goodwill et al., CHES 2011)

TVLA (Test Vector Leakage Assessment) is the standard methodology for
measuring side-channel leakage using Welch's t-test on power traces or
timing measurements.

MeissnerSeal uses **timing-mode TVLA** via the `dudect` framework, which applies
the same Welch's t-test to timing measurements rather than power traces.

### Methodology Binding

| Concept | TVLA / ISO 17825 | MeissnerSeal Implementation |
|---|---|---|
| Leakage model | Fixed vs. random input sets | Fixed: all-zero keys. Random: uniformly sampled keys |
| Statistical test | Welch's t-test | dudect implements this directly |
| Confidence threshold | |t| < 4.5 (ISO 17825 §5.5) | dudect reports t-statistic; threshold is |t| < 4.5 |
| Measurement count | ≥ 1M traces recommended | Beta: ≥ 1M timing samples per function |
| Scope | Cryptographic boundary | meissnerseal-crypto + meissnerseal-pqc (mandatory) |
| Binary-level verification | Complementary to TVLA | BINSEC/checkct (Beta) |

### Scope of Claim

Timing-mode TVLA does not detect power, EM, or fault injection side channels.
The scope of any side-channel claim is limited to: **constant-time timing
properties of software implementations on the host processor**, measured by
dudect following the TVLA methodology. See ADR-014 and security_assurance.md §7
for the full hierarchy and limitation statement.

---

## 6. SLSA — Supply-chain Levels for Software Artifacts

**Status:** SLSA Level 2 (MVP-0)
**Reference:** SLSA v1.0 (https://slsa.dev)

### Current Level Assessment

| SLSA Requirement | Level | Status |
|---|---|---|
| Build process is scripted | L1 | CI pipelines in `.github/workflows/` |
| Build triggers are auditable | L1 | GitHub Actions audit log |
| Provenance is generated | L2 | Active — `actions/attest-build-provenance@e8998f9` (v2) in ci-thorough.yml |
| Provenance is signed | L2 | Active — GitHub Actions OIDC signing |
| Build runs on hosted platform | L2 | GitHub-hosted runners (ubuntu-latest) |
| Build is isolated per build | L3 | GitHub Actions provides this; not yet formally attested |
| Source integrity verified | L3 | Partial — tag signing planned for Beta |

**Current level: SLSA L2** (signed provenance attestation active on every PR and manual trigger)
**Beta target: SLSA L3** (hermetic builds, formal source integrity)

### Provenance Attestation

Every PR build and manual trigger generates a signed SLSA provenance
document using `actions/attest-build-provenance@v2`. This records:
- Source commit digest
- Builder identity (GitHub Actions runner)
- Build invocation parameters
- Output artifact digest

Verifiers can check provenance using: `gh attestation verify <artifact>`

---

## 7. CWE Mapping Policy

**Status:** Active — applies to all Security Review Agent findings
**Reference:** MITRE CWE (https://cwe.mitre.org)

Every finding in a Security Review Agent report must include the applicable
CWE identifier. This makes findings machine-readable, comparable across reviews,
and linkable to the MITRE knowledge base.

### High-Relevance CWE Identifiers for MeissnerSeal

| CWE | Name | MeissnerSeal Context |
|---|---|---|
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | Wrong primitive or deprecated algorithm |
| CWE-330 | Use of Insufficiently Random Values | Non-OS entropy source |
| CWE-331 | Insufficient Entropy | Weak nonce or key generation |
| CWE-338 | Use of Cryptographically Weak PRNG | Custom or seeded RNG |
| CWE-323 | Reusing a Nonce, Key Pair in Encryption | Nonce reuse in AEAD |
| CWE-325 | Missing Cryptographic Step | Skipped HKDF domain separation |
| CWE-347 | Improper Verification of Cryptographic Signature | Authentication failure not caught |
| CWE-310 | Cryptographic Issues (parent) | Use when more specific CWE not applicable |
| CWE-312 | Cleartext Storage of Sensitive Information | Missing Zeroize, plaintext in logs |
| CWE-313 | Cleartext Storage in a File or on Disk | Unencrypted vault write |
| CWE-319 | Cleartext Transmission of Sensitive Information | Unencrypted transfer |
| CWE-385 | Covert Timing Channel | Timing side-channel in crypto boundary |
| CWE-203 | Observable Discrepancy | Secret-dependent branches |
| CWE-400 | Uncontrolled Resource Consumption | Unbounded parser input |
| CWE-190 | Integer Overflow or Wraparound | Arithmetic in crypto length calculations |
| CWE-125 | Out-of-bounds Read | Indexing slicing without bounds check |
| CWE-787 | Out-of-bounds Write | Buffer overflow in unsafe block |
| CWE-416 | Use After Free | Zeroized memory accessed post-drop |
| CWE-693 | Protection Mechanism Failure (parent) | Bypass of fail-closed behavior |

---

## 8. Future Targets (Not Current Scope)

### FIPS 140-3 (Cryptographic Module Validation)

FIPS 140-3 validation requires a NVLAP-accredited third-party lab and is a
multi-year, high-cost process. MeissnerSeal's design is **FIPS-ready**:

- All cryptographic primitives are from FIPS-approved algorithm families
  (AES-256, SHA-256, HMAC-SHA-256, HKDF-SHA-256)
- The OS CSPRNG delegation model (ADR-013) is consistent with FIPS 140-3
  approved entropy sources
- Key derivation follows SP 800-108 (KDF in counter mode via HKDF)
- No custom or unapproved primitives

FIPS 140-3 validation is a post-Production goal if there is institutional
demand. No validation target is committed without a sponsor.

### Common Criteria (ISO 15408)

MeissnerSeal's threat model, security assurance matrix, and protocol specifications
collectively constitute the foundation of a CC Security Target document.
EAL 4 (methodically designed, tested, and reviewed) is the typical target
for commercial security software.

CC evaluation requires a CCRA-authorized evaluation facility. This is a
post-Production, demand-driven goal. No EAL target is committed.
