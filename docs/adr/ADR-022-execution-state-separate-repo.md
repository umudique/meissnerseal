<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-022: Execution State in a Separate Local-Only Repository

**Status:** Accepted  
**Date:** 2026-06-07  
**Related:** ADR-020 (agent governance), ADR-018 (branch protection & CI),
             AGENTS.md, docs/agents/AGENT_PROMPT_TEMPLATE.md

---

## Context

Arcanum is developed by a single operator with AI agent assistance. Day-to-day
work needs live execution state — what task is being worked on, by which agent
role, in what order, blocked on what — held as a machine-parseable task graph so
agents can read and patch it cheaply.

This state is high-churn and ephemeral. Tracking it *inside* the main repository
would conflict with two existing decisions:

- **ADR-018** mandates signed commits and a linear, rebase-merged history. A
  source of truth that flips status fields many times per session would flood
  that history with "update workplan" noise and entangle ephemeral state with
  audited source.
- **ADR-020** keeps the main repo a clean, auditable professional artifact.

Yet the durable *records* this state references — decisions, finding remediation,
specs — must stay in the main repo where they are backed up, signed, and
auditable. So the question is where the **live, reconstructable** layer lives, not
the durable one.

The main repo already separates strategy (`mvp_roadmap.md`), rules (`AGENTS.md`),
decisions (`docs/adr/`), and findings (`docs/security/finding_register.yaml`).
Execution state is a fifth, distinct concern with a different lifecycle.

---

## Decision

**Adopted.** Live execution state lives in a **separate, local-only git
repository** (`arcanum-ops`), not in the main repo and not on any remote.

- **Source of truth:** `tasks.yaml` — a machine-parseable acyclic task graph
  (Task / Gate / Workstream nodes; `deps` and `triggers` edges). The primary
  consumer is an AI agent, so the source is structured YAML, not prose; humans
  read a derived narrative (`workplan.md`).
- **Local-only:** no remote, single machine. Backup is covered by the machine's
  home-directory backup. The durable records (ADRs, finding register) already
  live in the main repo on GitHub, so the ops repo holds nothing that needs
  independent backup.
- **No durable artifact lives there.** Decisions go to ADRs; finding remediation
  goes to `finding_register.yaml` (main repo). The ops repo holds only
  reconstructable, high-churn state and *links* (by ID) to durable records.
- **Token discipline as an invariant.** The hot path is `AGENTS.md` +
  `tasks.yaml` only; everything else is read on demand. `done` nodes are swept to
  an append-only `log/completed.md` so nothing finished is ever lost while the
  live graph stays small.
- **Consistency check (`analyze`).** At session close a cross-artifact check
  verifies reference closure, acyclicity, finding linkage, spec-ref existence, no
  lost work, and human-view sync — the local analogue of Spec-Kit's `/analyze`.

The full schema and protocol live in `arcanum-ops/README.md`; this ADR records
only *that* and *why* this layer is separate, for auditors reading the main repo.

---

## Alternatives Considered

**Track task state inside the main repo (e.g. a `TODO.md` or issues file):**  
Rejected. Pollutes the signed, linear history (ADR-018) with high-frequency churn
and entangles ephemeral state with audited source.

**GitHub Issues / Projects for task tracking:**  
Rejected for this phase. Single operator, single machine, offline-friendly. Issues
add a network dependency and an external surface for state that is purely internal
execution bookkeeping. (Tools like Spec-Kit's `taskstoissues` target multi-
contributor teams; that benefit does not apply here.)

**A long-lived branch in the main repo for ops state:**  
Rejected. Still couples ops churn to the main repo's tooling and review flow, and
complicates rebase-merge.

**Prose workplan only (no machine-parseable graph):**  
Rejected. The primary consumer is an agent; a prose plan is costly to parse and
patch and cannot be checked for DAG integrity. Prose is kept as the *derived*
human view, not the source.

---

## Consequences

- The main repo's history stays clean and auditable; execution churn is isolated.
- Agents operate from a small, structured hot path, minimising token cost.
- Live state has full git versioning (history, diff, branch) without touching the
  main repo's integrity.
- A second repository exists that an auditor of the main repo will not see; this
  ADR plus the cross-references (`finding_register.yaml`, ADR links) document its
  existence and boundary so the audit trail remains complete.
- The ops repo is not a deliverable and is excluded from the main repo's build,
  CI, and release artifacts by construction (it is a sibling directory, not a
  submodule).
- If the project grows to multiple contributors, this decision must be revisited:
  shared execution state would then need a remote or a move to Issues/Projects.
