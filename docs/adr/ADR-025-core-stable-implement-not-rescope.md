<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-025: meissnerseal-core Reaches Stable by Implementation, Not Re-Scoping

**Status:** Accepted  
**Date:** 2026-06-08  
**Related:** ADR-006 (Argon2id params), ADR-020 (agent governance / API Stable
is a human gate), ADR-024 (Kani type-level proofs), crypto_design.md §2–§3,
vault_format_v1.md §7–§8, meissnerseal-crypto CONTRACT G-05, meissnerseal-core CONTRACT
P-02; finding_register F-01/F-02/F-03/F-09/F-10/F-11

---

## Context

The MVP-0 Stable-readiness milestone review (Consistency Agent + Security
Review Agent, 2026-06-08, branch `feat/mvp0-test-vectors`) **blocked** marking
`meissnerseal-core` as `API Status: Stable`. The reviews surfaced a single root
problem: **the core CONTRACT promises behavior the implementation does not yet
provide.** The contract and the code disagree, and "Stable" would freeze that
disagreement.

The concrete contradictions:

- **F-09 (CWE-693):** `vault/engine.rs create()` derives keys and returns a
  session but never serializes or persists a vault file — no
  serialize → encrypt → temp-file → fsync → rename → fsync-parent crash-safe
  write. CONTRACT.md and vault_format_v1.md §8 promise a durable vault.
- **F-01 / F-02 (CWE-345):** `create()` and `unlock()` build the WrappedRootKey
  AAD with all-zero `record_id` / `revision_id`. Canonical AAD
  (vault_format_v1.md §7) requires the real identifiers; CONTRACT P-02 requires
  canonical AAD. `parse_record_frame()` does not even expose the stored
  revision.
- **F-03 (CWE-1188):** `keys/hierarchy.rs` hardcodes the Argon2id parameters
  instead of reading the KDF parameter TLVs from the vault header. This
  contradicts ADR-006 and meissnerseal-crypto CONTRACT G-05 (no hardcoded
  parameters in the implementation chain).
- **F-10 (CWE-325):** Session derivation expands **4** HKDF subkeys, while
  crypto_design.md §3 specifies **7** registry subkeys (the test vectors in
  `cross_verify.py` also define all 7) — a vector-vs-implementation gap.
- **F-11 (CWE-684):** CONTRACT.md states `create()` returns a `VaultHandle` and
  that a `VaultSession` is produced only via `unlock()`, but the implementation
  returns a `VaultSession` from `create()`.

F-01/F-02/F-03 were previously logged as "deferred to Phase 3" and marked
non-blocking. That classification was correct for MVP-0 *functionality* (the
zero-ID weakness does not manifest while persistence is inactive), but it is
**not** compatible with declaring the API *Stable*: a Stable contract must not
quietly carry deferred behavior that the contract itself promises.

Two honest resolutions exist:

- **(A) Implement** the missing behavior so the code rises to meet the
  contract.
- **(B) Re-scope** the contract/specs downward (with an ADR) so they describe
  only what the code does today, then call that narrower surface Stable.

---

## Decision

Adopt **Option A: meissnerseal-core reaches Stable by implementation, not by
re-scoping.**

We will implement the behavior the CONTRACT already promises, rather than
narrowing the contract to the current implementation. The core's public
surface — durable vault persistence, canonical AAD binding, header-sourced KDF
parameters, and the full key hierarchy — stays as specified; the
implementation is completed to match it before the Stable mark is applied.

Rationale:

- The specs (vault_format_v1, crypto_design) and the cross-verified test
  vectors already describe the full, correct behavior. Re-scoping would mean
  weakening authoritative documents to match a temporary implementation state —
  the wrong direction for a security product where the spec is the source of
  truth.
- The gaps are security-relevant (AAD substitution resistance, durable writes,
  parameter integrity). A Stable API is the foundation dependents build on;
  shipping it with these behaviors deferred would propagate the weakness
  upward.
- The cost (notably the crash-safe write path) is accepted as MVP-0 work pulled
  forward from Phase 3, with the understanding that it carries new
  implementation and a fresh security review.

Marking `meissnerseal-core` `API Status: Stable` remains a human gate (ADR-020) and
occurs only after all six findings are resolved and re-reviewed.

---

## Alternatives Considered

**Option B — re-scope the contract to the MVP-0 surface:**  
Rejected. Faster and lower-risk, but it shrinks the meaning of "Stable" and
requires weakening the specs and CONTRACT to match an implementation that is
known to be incomplete. For a secrets vault whose specs are the trust anchor,
moving the authoritative documents down to the code is the wrong direction.

**Mark Stable now and track the gaps as known issues:**  
Rejected outright — this is exactly what the milestone review blocked. It
freezes a contract that makes promises the code does not keep.

---

## Consequences

- `meissnerseal-core` stays `Unstable` until F-01, F-02, F-03, F-09, F-10, F-11 are
  resolved and a follow-up security/consistency review clears them.
- A roadmap of implementation tasks is added to meissnerseal-ops under the CORE
  workstream (crash-safe persistence, AAD record/revision binding incl.
  exposing the stored revision from `parse_record_frame`, header-read KDF
  params, full 7-subkey hierarchy, CONTRACT reconciliation).
- Backlog items P3-1..P3-4 (the original Phase-3 deferrals for these gaps) are
  pulled into MVP-0 scope and superseded by the CORE roadmap.
- The crash-safe write path is new security-relevant code and triggers a new
  milestone review before Stable.
- Specs, CONTRACT, and ADRs remain the authoritative description; no
  authoritative document is weakened by this decision.
