<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-020: AI-Assisted Development and Agent Governance Model

**Status:** Accepted  
**Date:** 2026-06-06  
**Related:** AGENTS.md, docs/agents/AGENT_PROMPT_TEMPLATE.md,
             docs/development/git_workflow.md, ADR-017 (extended toolchain)

---

## Context

Arcanum is developed with AI agent assistance (Claude Code). Agents accelerate
implementation but introduce a class of risks specific to security-critical
software:

- Agents may introduce subtle cryptographic mistakes that pass tests and lint
- Agents may add dependencies or change versions without human awareness
- Agents may implement features before the design is stable, creating churn
- Agents may produce plausible-looking but incorrect security reasoning
- Agent-authored code may be harder to audit if authorship is opaque

The question is not whether to use agents, but how to constrain them so their
output meets the same bar as human-authored code on a security project.

---

## Decision

### Governance document — AGENTS.md

**Adopted.** `AGENTS.md` at the repository root is the authoritative reference
for any agent working in this codebase. It defines:

- Mandatory pre-task checklist (read specs, understand threat model)
- Cryptographic invariants that cannot be violated under any circumstance
- Phase gates: what may be implemented at each MVP phase
- Dependency gate: agents cannot add, remove, or version-bump dependencies
  without human approval
- Tool failure protocol: what to do when CI tools report issues
- Commit protocol: formatting, content, and security constraints
- Security review format: CWE numbers mandatory per finding

`AGENTS.md` is version-controlled and subject to the same review process as
code. It is not gitignored.

### Cryptographic hard stops

The following constraints are absolute — agents may not override them
regardless of context, performance argument, or apparent necessity:

- No custom cryptographic primitives (use RustCrypto ecosystem, ADR-011)
- No custom RNG — OS CSPRNG only (ADR-013)
- No secret values in logs, argv, errors, or test output
- No `==` on secrets — use `subtle::ConstantTimeEq`
- All secret types must be `Zeroize + ZeroizeOnDrop` with redacted `Debug`
- Fail-closed always: ambiguous state must deny access, not grant it

These are enforced by code review, clippy lints, and the security engineering
protocol, not just documentation.

### Phase gate model

Implementation is gated by MVP phase. An agent may not begin implementation
of a feature belonging to a phase that has not been explicitly authorised by
the human developer. This prevents speculative implementation that creates
debt before the design is stable.

Current gate: **pre-MVP-0** — infrastructure and design only.

### Dependency gate

Agents cannot:
- Add new dependencies to any `Cargo.toml`
- Remove existing dependencies
- Change dependency version constraints
- Mark any crate API as `Stable`

These actions require explicit human approval. Rationale: dependency changes
affect the supply chain, license compliance, and the security surface. They
must be a conscious decision, not an agent convenience.

### Agent prompt template

`docs/agents/AGENT_PROMPT_TEMPLATE.md` provides a structured prompt format
for security-sensitive tasks. It mandates:

- Explicit pre-task checklist (specs read, threat model understood)
- Security finding format: `file:line | CWE-XXX | description | severity`
- Verification section: tools run, results, test vectors

**Amendment 2026-06-07 (format, non-substantive).** The template is now
*render-from-source* rather than copy-paste verbatim blocks: a shared `common`
block plus a per-role delta, expanded to a prose prompt via the render recipe in
`AGENT_PROMPT_TEMPLATE.md §1`. The decision to use structured, role-specific
prompts is unchanged; only its encoding was deduplicated (~70% less marginal
read per prompt). See also ADR-022 for where live execution state is tracked.

### No AI attribution in commits

**Adopted.** Commits do not carry `Co-Authored-By` or equivalent AI
attribution trailers. Rationale:

- Commit history is a professional artifact and an audit trail
- AI attribution reveals internal development tooling to external auditors,
  competitors, and future reviewers in ways that may not be warranted
- Responsibility for every commit rests with the human author who reviewed,
  staged, and committed it — regardless of how the content was drafted
- The pre-commit hook, CI pipeline, and code review process apply identically
  to agent-authored and human-authored code

This policy was applied retroactively to the entire commit history at project
inception.

### AGENTS.md is kept in the repository

**Adopted.** `AGENTS.md` is not gitignored. It is project documentation
equivalent to `CONTRIBUTING.md`. Version-controlling it means:
- Governance rules are auditable and attributable
- Contributors (human or agent) encounter them immediately on clone
- Changes to governance are tracked and reviewable

`.claude/` tool configuration (if it ever exists) would be gitignored as it
is personal tooling state, not project documentation.

---

## Alternatives Considered

**No governance document; rely on prompts:**  
Rejected. Prompt-only governance is not auditable, not version-controlled,
and not visible to future contributors. It also fails to prevent agents from
violating constraints that were not explicitly stated in the current session.

**Formal agent sandboxing (no filesystem write, no git access):**  
Rejected for current phase. The overhead of sandboxing is disproportionate
for a single-developer project. The governance document and pre-commit hook
provide equivalent protection at lower cost.

**AI attribution in commits:**  
Rejected. See "No AI attribution in commits" above. The decision was made
at project inception and applied retroactively.

**Separate `agents/` branch for agent work:**  
Considered. A dedicated branch would make agent contributions visually
separable. Rejected: it adds merge overhead and the phase gate model already
constrains what agents can change. The pre-commit hook + CI provide the
correctness gate regardless of authorship.

---

## Consequences

- All agent-authored changes pass the same pre-commit and CI bar as
  human-authored changes.
- Governance rules are auditable in git history.
- Dependency and API surface changes require human approval, creating a
  natural checkpoint for supply-chain review.
- No AI attribution appears in commit history, keeping the audit trail clean.
- When the project grows to multiple developers, AGENTS.md may need a section
  on multi-agent coordination and conflict resolution.
