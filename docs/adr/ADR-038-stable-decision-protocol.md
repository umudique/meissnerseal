<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-038: Crate Stable Decision Protocol — Cascade Visibility and Revocation

**Status:** Accepted  
**Date:** 2026-06-26  
**Related:** AGENTS.md §11 (Dependency Gate), §12 (Phase Gate),
             docs/security/finding_register.yaml

---

## Context

AGENTS.md §11 defines a dependency gate: a crate must not begin
implementation until all its dependencies have `API Status: Stable`.
The Stable marking is a one-way gate — it unlocks downstream work.

Two risks are unaddressed:

**Cascade visibility.** When a Stable decision is made, the reviewer
sees only the crate under review. The downstream crates that will be
unlocked — and the work that will begin as a result — are not part of
the decision frame. A Stable decision is implicitly a go-ahead for the
entire downstream cone, but the decision is made without seeing the
cone.

**No revocation path.** Once a crate is marked Stable and downstream
work begins, there is no defined protocol for what happens when a
post-Stable finding reduces confidence in the Stable marking. The
finding_register.yaml may record an `open` finding against a Stable
crate, but the downstream work continues. There is no "Stable Under
Review" state and no defined cascade effect.

Both risks are instances of OWASP ASI08 (Cascading Failures): a
decision made at one layer propagates silently through a dependent
chain.

---

## Decision

### 1. Stable decision checklist

When proposing a crate for Stable marking, the proposer must answer
the following questions explicitly in the PR description or issue:

```
Cascade impact:
  - Which crates does this Stable decision unlock?
  - Is there an active plan to begin any of those crates immediately?
  - If yes: are the Stable-gated preconditions for those crates met
    beyond this one dependency?

Finding register:
  - Are there any open findings against this crate in
    docs/security/finding_register.yaml?
  - If yes: have all Critical and High findings been resolved or
    formally accepted with documented rationale?

Review coverage:
  - Consistency Agent verdict: Clear?
  - Security Review Agent verdict: approved or approved_with_reservations?
  - If approved_with_reservations: are the reservations documented
    and accepted by the human owner?
```

The Stable marking must not be applied until all questions are
answered. "I don't know which crates this unlocks" is not an
acceptable answer — check AGENTS.md §11 dependency order.

### 2. Stable Under Review

A crate may be moved from `Stable` to `Stable (Under Review)` when:

- A new finding is registered against it at Critical or High severity.
- A spec change invalidates a previously verified property.
- A dependency receives a CVE that affects the crate's security claims.

The `Stable (Under Review)` status:
- Does not stop in-progress downstream work unless the finding is
  Critical and directly affects the downstream interface.
- Does stop new downstream crates from beginning implementation.
- Requires a human decision to resolve: either return to `Stable`
  (finding resolved or accepted) or revert to `Unstable` (finding
  requires rework).

The transition is recorded in the crate's CONTRACT.md header:

```
**API Status:** Stable (Under Review)
**Under Review Since:** YYYY-MM-DD
**Reason:** [one sentence — reference finding ID if registered]
```

### 3. Revert to Unstable

A crate reverts from Stable to Unstable when:

- A Critical finding cannot be resolved without breaking the public API.
- A spec change requires the public API to change.

Revert to Unstable triggers the following:
- All downstream crates that have not yet reached their own Stable
  marking are paused — they must not add new implementation that
  depends on the changed interface until the upstream crate reaches
  Stable again.
- In-progress work is not deleted, but a new Phase 1 review is
  required for any downstream module that called the affected API.
- A new finding is registered documenting the revert and its cause.

The revert is recorded in CONTRACT.md:

```
**API Status:** Unstable
**Previously Stable:** YYYY-MM-DD to YYYY-MM-DD
**Revert Reason:** [one sentence — reference finding ID]
```

### 4. No self-approval

A Stable decision may not be made by the same person who authored
the Phase 2 implementation. The Security Review Agent and Consistency
Agent verdicts are prerequisites, not substitutes for human review.

---

## Alternatives Considered

**Do nothing.** The current protocol (Consistency Agent + Security
Review Agent + human approval) is sufficient for the current project
size. Accepted as true, but the absence of a revocation path means
the protocol degrades under pressure: a Critical finding post-Stable
has no defined response, and the natural outcome is ignoring it.

**Automated cascade blocking.** A CI check that reads CONTRACT.md
API Status and blocks downstream PRs when a dependency is not Stable.
Viable but premature — the dependency chain is short and manually
trackable now. Worth revisiting at MVP-2 completion when more crates
are active.

---

## Consequences

- Stable decisions require slightly more ceremony (cascade checklist).
- "Stable Under Review" adds a state that tooling does not enforce —
  it is a human-maintained marker in CONTRACT.md.
- Revert-to-Unstable is disruptive but rare; defining the path now
  avoids ad hoc decisions under pressure.
- The finding register becomes load-bearing for Stable decisions:
  open Critical/High findings block the transition.
