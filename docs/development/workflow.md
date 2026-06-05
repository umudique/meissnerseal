# Arcanum Development Workflow

**Audience:** Human developer and all agents  
**Read alongside:** AGENTS.md, docs/security/security_engineering_protocol.md

---

## 1. The Two Actors

| Actor | Role | Authority |
|---|---|---|
| Human | Defines tasks, approves decisions, gives final sign-off | Final authority on all decisions |
| Agent | Implements, verifies, reports | No self-authorization on scope, dependency, or spec changes |

Every task flows through both actors. Agents do not self-approve anything
that changes a contract, a spec, or a dependency.

---

## 2. Full Task Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│  HUMAN: Define task                                         │
│  "Implement KDF_ARGON2ID_V1 in arcanum-crypto"              │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  ARCHITECT AGENT (if structural change)                     │
│  • Is a new ADR needed?                                     │
│  • Does a spec need updating?                               │
│  • Are existing ADRs still consistent?                      │
│                                                             │
│  Output: new ADR draft OR "no ADR needed"                   │
└──────────────────────────┬──────────────────────────────────┘
                           │
                     Human reviews ADR
                     Human approves / revises
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  SPEC AGENT (if spec needs updating)                        │
│  • Updates relevant spec file                               │
│  • Keeps specs and ADRs consistent                          │
│                                                             │
│  Output: updated spec section                               │
└──────────────────────────┬──────────────────────────────────┘
                           │
                     Human reviews spec change
                     Human approves / revises
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  TEST VECTOR AGENT (if cryptographic operation)             │
│  • Produces known-answer test vector in test-vectors/       │
│  • Cross-verifies with Python or SageMath                   │
│                                                             │
│  Output: test-vectors/<profile>.json + cross-verify script  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                     Human reviews test vector
                     Human approves / revises
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  IMPLEMENTATION AGENT (Crypto / PQC / Core / Security / ...) │
│                                                             │
│  PHASE 1 — Tests and contracts only                         │
│  • Declares scope (AGENTS.md §10)                           │
│  • Checks dependency gate (AGENTS.md §11)                   │
│  • Writes /// # Contract block                              │
│  • Writes test vector reference or proptest property        │
│  • Writes fuzz target skeleton (if parser)                  │
│  • Runs: cargo test (compile only, may fail)                │
│                                                             │
│  Output: Phase 1 report for human review                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
                     Human reviews Phase 1
                     Human approves / revises
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  IMPLEMENTATION AGENT — PHASE 2                             │
│  • Writes implementation to pass Phase 1 tests              │
│  • Runs full static tool suite (AGENTS.md §5)               │
│  • Runs Miri if crypto crate                                │
│  • Writes completion report (AGENTS.md §13)                 │
│                                                             │
│  Output: completion report + passing tool suite             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                     Human reviews implementation
                     Human approves / requests revision
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  FUZZ AGENT (if task includes a parser)                     │
│  • Fills in the fuzz target skeleton                        │
│  • Runs: cargo fuzz build + 30s smoke run                   │
│                                                             │
│  Output: completed fuzz target, no crashes                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
              ─── MILESTONE BOUNDARY ──────────────────────
              (Human triggers at MVP boundary or as needed)
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  CONSISTENCY AGENT                                          │
│  • Checks spec ↔ implementation                             │
│  • Checks ADR ↔ CONTRACT.md                                 │
│  • Reports Critical (blocker) and Advisory (non-blocking)   │
│                                                             │
│  Output: consistency report                                 │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  SECURITY REVIEW AGENT                                      │
│  • Scorecard: 6 axes, 0–5 each                              │
│  • Approval recommendation                                  │
│                                                             │
│  Output: structured review report                           │
└──────────────────────────┬──────────────────────────────────┘
                           │
                     Human: final approval
                     or requests revision
```

---

## 3. Human Checkpoints

The human has a required checkpoint at each of these moments:

| Checkpoint | What to review |
|---|---|
| ADR approval | Is the decision correct? Are alternatives considered? |
| Spec approval | Is the spec precise? Any ambiguity? |
| Test vector approval | Does the known answer make sense? Is it independently verified? |
| Phase 1 approval | Are preconditions complete? Are tests correct rules, not examples? |
| Implementation approval | Does code match spec? Completion report clean? |
| Milestone approval | Consistency and security review findings addressed? |

Human approval is required before the next phase begins.
Agents do not self-advance through checkpoints.

---

## 4. Tool Pipeline by Trigger

```
Every commit — pre-commit hook (~25s):
  cargo fmt --check
  cargo check --workspace --all-targets
  cargo clippy --workspace --all-targets --all-features -D warnings
  cargo deny check
  cargo audit

Every push — CI fast (~5 min):
  All pre-commit checks
  + cargo test --workspace
  + cargo geiger (informational, does not fail)

PRs to main + nightly — CI thorough:
  + Miri (arcanum-crypto, arcanum-pqc, arcanum-security, arcanum-ffi)
  + cargo fuzz build + 30s smoke (all 6 targets)
  + AddressSanitizer
  + cargo vet (informational)

Milestone (human-triggered):
  + Extended fuzzing (24h+)
  + dudect timing analysis
  + SBOM generation
  + Consistency Agent
  + Security Review Agent

Release gate:
  + All above
  + Reproducible build verification (Production+)
  + External protocol review (Beta+)
```

---

## 5. Dependency Gate — Implementation Order

Crates must reach `API Status: Stable` before dependents begin:

```
Batch 1 (independent, can parallelize):
  arcanum-crypto
  (no dependencies on other arcanum crates)

Batch 2 (after arcanum-crypto is Stable):
  arcanum-pqc
  arcanum-security

Batch 3 (after arcanum-pqc and arcanum-security are Stable):
  arcanum-core

Batch 4 (after arcanum-core is Stable):
  arcanum-ffi
  arcanum-cli
  arcanum-sync-server
```

To promote a crate to Stable, update its CONTRACT.md:
```
**API Status:** Stable
```
This change requires human approval and a commit.

---

## 6. Phase Gate Summary

| Agent | Phase 1 required? | Human review between phases? |
|---|---|---|
| Crypto Agent | Yes | Yes |
| PQC Agent | Yes | Yes |
| Core Agent | Yes | Yes |
| Security Agent | Yes | Yes |
| FFI Agent | Optional | Optional |
| CLI Agent | No | No |
| Sync Server Agent | No | No |
| Fuzz Agent | No | No |
| Test Vector Agent | No | No |
| Spec Agent | No | No |
| Architect Agent | No | No |

---

## 7. What Agents Cannot Do Without Human Approval

```
Change a dependency version in Cargo.toml
Change an API marked Stable in CONTRACT.md
Modify specs/ (Spec Agent only, with human approval)
Modify docs/adr/ (Architect Agent only, with human approval)
Mark a crate API Status: Stable
Dismiss a Miri failure
Dismiss a cargo audit CVE
Add a #[allow(...)] lint exception without REASON comment
Proceed after 2 failed tool fix attempts
Begin Phase 2 before Phase 1 is approved
```

---

## 8. Completion Report Template

```markdown
## Completion Report

**Role:** [agent role]
**Task:** [task description]

**Scope Declaration (actual):**
- Modified: [list]
- Read: [list]

**Phase 1 output:** [test/property/fuzz — or N/A]
**Phase 1 approved by:** [name or N/A]

**Tests written:**
- [name]: [what it verifies]

**Tool results:**
- cargo fmt:    PASS / FAIL
- cargo check:  PASS / FAIL
- cargo clippy: PASS (0 warnings) / FAIL
- cargo test:   PASS (N tests) / FAIL
- cargo audit:  PASS / FAIL
- Miri:         PASS / FAIL / N/A

**CONTRACT.md changes:** None / [describe]
**Spec deviations:** None / [describe + ADR opened]
**Open questions:** None / [list]
```
