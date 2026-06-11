<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-032 — Version Policy

**Status:** Accepted  
**Date:** 2026-06-11  
**Related:** docs/architecture/mvp_roadmap.md

---

## Context

MeissnerSeal has seven defined milestones (MVP-0 through MVP-6). A version policy
is needed to answer three questions:

1. What does a version number communicate to a user or downstream integrator?
2. When does `1.0.0` ship?
3. How do pre-release suffixes map to project maturity?

The milestone execution order does not follow numeric sequence. Per
`mvp_roadmap.md` §2, MVP-2 (Transfer) is prioritized over MVP-1 (Desktop)
because transfer proves the core security thesis before desktop UI makes
the product demonstrable.

---

## Decision

### Scheme: milestone-based minor bumps, priority order

Version numbers follow the milestone execution priority, not milestone numbers.

| Version | Milestone | Pre-release |
|---------|-----------|-------------|
| `0.1.0` | MVP-0 — Local vault, CLI | `-alpha` |
| `0.2.0` | MVP-2 — X-Wing transfer, hybrid KEM envelope | `-alpha` |
| `0.3.0` | MVP-1 — Desktop app, FFI | `-alpha` |
| `0.4.0` | MVP-3 — Encrypted sync, TLA+ model | `-beta` |
| `0.5.0` | MVP-4 — Browser extension | `-beta` |
| `0.6.0` | MVP-5 — Managed sync, external review | — |
| `0.7.0` | MVP-6 — Teams, enterprise | — |
| `1.0.0` | Technical maturity gate (see below) | — |

Each milestone sets the *floor* for the next minor version. Patch releases
(`0.x.y`, y > 0) may be cut between milestones for bug fixes, security
patches, or non-breaking additions.

### Pre-release suffixes

- `-alpha`: vault format not stable, no production use
- `-beta`: format stable, external review in progress or complete, no
  production use recommended without independent assessment
- No suffix: production-ready for the scope of that milestone

### `1.0.0` criteria

`1.0.0` is a technical maturity gate, not a milestone. It requires all of:

1. Vault format frozen — no breaking changes without a new format version
2. Pure PQC transition complete — ML-KEM-768 standalone, no classical fallback
   required for new envelopes
3. Formal verification gates complete — ProVerif (transfer), TLA+ (sync),
   Kani bounds proofs (crypto)
4. `meissnerseal-core` API stable — semver-checks enforced, no breaking changes
   since last minor

External security audit is recommended before `1.0.0` but is not a blocker.
Audit status is documented in release notes regardless.

---

## Alternatives Considered

### Calendar versioning (e.g. `2026.06`)

Rejected. Calendar versions communicate release date, not capability or
stability level. A secrets vault user needs to know "is this production-ready"
from the version number, not "when was this released."

### Sequential MVP numbering (0.1 → MVP-0, 0.2 → MVP-1, ...)

Rejected. This would assign `0.2.0` to MVP-1 (Desktop UI) even though
MVP-2 (Transfer) ships first. The version number would not reflect the
actual release sequence, creating confusion in the changelog and git history.

### Tie `1.0.0` to external audit completion

Rejected. External audit depends on third-party availability, budget, and
timing — none of which are measures of technical correctness. `1.0.0`
must be achievable on technical criteria alone; audit completion is
documented as a release note, not a gate.

### Use only `-alpha` and `-beta`, no suffix-free `0.x`

Rejected. MVP-5 and MVP-6 deliver production SaaS and enterprise features.
Marking those releases `-beta` when they are billable commercial products
would be misleading. Suffix-free `0.x` correctly signals "stable for this
scope, not yet format-frozen."

---

## Consequences

- Each milestone completion requires a `Cargo.toml` workspace version bump
  and a signed git tag (`git tag -s vX.Y.Z[-suffix]`).
- Patch releases follow the same signed-tag protocol; no minor bump required.
- The roadmap table in `README.md` and `docs/architecture/mvp_roadmap.md`
  must be kept consistent with this policy.
- `cargo semver-checks` enforces API stability on `meissnerseal-core` from
  `API Status: Stable` forward (ADR-017); breaking changes require a minor bump.
