<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-016: Standards Conformance Strategy

**Status:** Accepted
**Date:** 2026-06-06
**Deciders:** Project leads
**Related:** ADR-013 (OS CSPRNG), ADR-014 (side-channel hierarchy),
             ADR-015 (mathematical verification), ADR-011 (RustCrypto ecosystem)

---

## Context

Arcanum is designed for critical secrets storage with military/intelligence-grade
security ambitions. Without an in-house security certification team, the project
must align with recognized external standards to:

1. Provide a structured checklist against which gaps can be identified
2. Give regulated-industry and institutional adopters a familiar vocabulary
3. Avoid security-theater: standards must add genuine assurance, not only labels

The question is which standards to target, at which level of rigor, and when.

---

## Decision

Adopt five Tier 1 standards immediately as design targets and working environment
discipline. Defer Tier 2 certification processes (FIPS 140-3, Common Criteria)
until post-Production with explicit sponsor demand.

### Tier 1 Standards (Adopted)

**CNSA 2.0 (NSA Commercial National Security Algorithm Suite)**
- Rationale: Arcanum already uses ML-KEM-768 + X25519 hybrid (MVP-2) and
  AES-256 / XChaCha20-Poly1305 with SHA-256. CNSA 2.0 alignment is a
  natural consequence of the existing architecture.
- Obligation: Maintain a CNSA 2.0 algorithm mapping table in
  `docs/security/standards_conformance.md §2`. Do not add classical-only
  key agreement paths. Track ML-DSA adoption for device signing.

**NIST SSDF (SP 800-218, Secure Software Development Framework)**
- Rationale: SSDF is the federal standard for secure software development.
  Our existing practices (threat model, agent roles, phase gates, CI tools,
  responsible disclosure) already cover most of it. A mapping document
  provides structure and identifies gaps without requiring process changes.
- Obligation: Maintain the SSDF practice mapping table in
  `docs/security/standards_conformance.md §3`. Review the mapping at each MVP
  milestone.

**NIST SP 800-90B (Entropy Source Validation)**
- Rationale: Arcanum's OS-CSPRNG-only policy (ADR-013) delegates entropy
  responsibility to the OS, which is the correct design. SP 800-90B requires
  that this delegation be explicitly documented and the platform entropy
  sources be identified.
- Obligation: Maintain the platform entropy source table in
  `docs/security/standards_conformance.md §4`. Re-evaluate when adding a
  new platform target.

**TVLA / ISO 17825 (Test Vector Leakage Assessment Methodology)**
- Rationale: The `dudect` timing side-channel tool (Layer 7 in the security
  engineering protocol) implements TVLA methodology informally. Binding it
  explicitly to ISO 17825 / TVLA strengthens the evidentiary claim and sets
  a precise measurement threshold (|t| < 4.5).
- Obligation: Document the TVLA methodology binding in
  `docs/security/standards_conformance.md §5`. Enforce the |t| < 4.5
  threshold as a Beta release gate. Document scope limitations: this covers
  timing only, not power/EM/fault.

**SLSA (Supply-chain Levels for Software Artifacts)**
- Rationale: Arcanum already has scripted CI builds (SLSA L1). Adding
  `actions/attest-build-provenance@v2` in the release workflow advances to
  SLSA L2 with minimal effort. Signed provenance attestation is the single
  highest-value supply chain improvement available now.
- Obligation: Current state is SLSA L2 (provenance attestation active on every
  PR and manual trigger). Beta target is SLSA L3 (hermetic builds).
  See `docs/security/standards_conformance.md §6`. Provenance job in `ci-thorough.yml`.

**CWE Mapping in Security Review Reports**
- Rationale: CWE identifiers make findings machine-readable and comparable.
  They cost nothing to add and eliminate ambiguity in finding descriptions.
- Obligation: Every Security Review Agent finding must include a CWE number.
  Enforced in `AGENT_PROMPT_TEMPLATE.md`. A reference table of high-relevance
  CWEs is maintained in `docs/security/standards_conformance.md §7`.

### Tier 2 Standards (Deferred, Design-Ready)

**FIPS 140-3** — Design is FIPS-ready (FIPS-approved primitives, SP 800-90B
entropy delegation, SP 800-108 KDF). Formal validation is a post-Production
goal requiring a NVLAP lab and dedicated effort. No timeline committed.

**Common Criteria (ISO 15408)** — Existing threat model and security assurance
documents form the foundation of a CC Security Target. EAL 4 is the likely
target for commercial security software. Evaluation requires a CCRA lab.
No timeline committed.

---

## Alternatives Considered

**Adopt FIPS 140-3 as immediate target**
Rejected. FIPS validation is expensive (time, money, lab) and irrelevant
until the software is production-stable with institutional demand.

**Adopt only internal standards, no external mapping**
Rejected. External standards provide structured checklists that are harder
to satisfy by coincidence. They also provide a vocabulary for adopters who
evaluate security products against known frameworks.

**Adopt ISO 27001 (information security management)**
Rejected. ISO 27001 is an organizational management standard, not a software
engineering standard. It applies to a security program, not a codebase. Relevant
if Arcanum becomes an organization with managed SaaS; premature now.

---

## Consequences

### Positive

- CNSA 2.0 alignment table serves as a permanent checklist for algorithm choices.
- SSDF mapping identifies practice gaps at each milestone review.
- SP 800-90B documentation satisfies the transparency requirement without
  adding implementation burden.
- TVLA threshold (|t| < 4.5) gives the dudect Beta gate a precise, defensible
  acceptance criterion.
- SLSA L2 provenance attestation provides cryptographic evidence of build
  integrity with minimal CI cost.
- CWE identifiers make Security Review Agent findings comparable across reviews.

### Negative / Costs

- Conformance documents require maintenance. If architecture changes, the
  mapping tables must be updated.
- SLSA L2 attestation requires `id-token: write` permission in the release
  workflow. This must be scoped narrowly to the provenance job.
- TVLA coverage is limited to timing side-channels. The |t| < 4.5 threshold
  cannot be used to claim immunity from power or EM side-channels.

### Constraints Introduced

- Security Review Agent findings must include CWE numbers from this commit.
- New algorithm selections must be checked against the CNSA 2.0 mapping table.
- Adding a new platform target requires updating the SP 800-90B entropy table.
- SSDF mapping must be reviewed at every MVP milestone.
