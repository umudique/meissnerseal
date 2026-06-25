<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# MeissnerSeal Git Workflow

**Status:** Authoritative reference — all agents and contributors must follow
**Read by:** Every agent before creating any commit
**Related:** [AGENTS.md](../../AGENTS.md), [workflow.md](workflow.md)

---

## 1. Core Principles

Every commit must be:

- **Atomic** — one logical change. A commit that adds a feature and fixes an
  unrelated bug must be split into two commits.
- **Self-contained** — the codebase must compile and all tests must pass at
  every commit. A broken intermediate state is never acceptable, even on a
  feature branch.
- **Traceable** — the subject line must identify what changed; the body must
  explain why. Reading the log should give a clear picture of the project
  history without opening files.
- **Secure** — no secret values, credentials, real vault data, private keys,
  or internal file paths outside the repository appear anywhere in any commit
  message or test fixture.

---

## 2. Commit Message Format

```
<type>(<scope>): <imperative subject>          ← 50 chars ideal, 72 max
<blank line>
<body — explain WHY, not WHAT>                 ← 72 chars per line
<blank line>
<footer>                                       ← Closes #N, BREAKING CHANGE
```

All four parts are expected for non-trivial changes. Subject-only commits are
acceptable only for genuinely trivial changes (typo, whitespace).

---

## 3. Type Prefixes

| Type | When to use |
|---|---|
| `feat` | Adds new capability, module, or behavior visible in production or agent use |
| `fix` | Corrects a bug in existing behavior |
| `docs` | Documentation only — specs, ADRs, guides, READMEs, CONTRACT.md |
| `test` | Adds or modifies tests without touching production code |
| `ci` | CI/CD workflow files, GitHub Actions, pre-commit hook changes |
| `chore` | Toolchain, dependency update, project scaffolding (no behavior change) |
| `refactor` | Code restructure with no behavior change |
| `perf` | Performance improvement with no behavior change |
| `security` | Security fix — use this instead of `fix` when the change closes a security issue |

**Rules:**
- Lowercase only. No uppercase type, no type without colon.
- Use `security:` for any commit that patches a vulnerability, removes a
  forbidden pattern, or closes a security finding.
- `feat:` and `fix:` are for code changes. Documentation additions are `docs:`.

---

## 4. Scope (Optional)

Scope is the crate or area affected, in parentheses after the type:

```
feat(meissnerseal-crypto): add HKDF-SHA256 key derivation
fix(meissnerseal-ffi): release secret view handle on panic path
docs(adr): add ADR-017 for replay window size
ci(thorough): add Kani bounded model checking job
```

Use scope when the subject is otherwise ambiguous about which crate is affected.
Omit scope when the change is workspace-wide or the subject already names the
crate.

---

## 5. Subject Line Rules

```
✓ feat: add XChaCha20-Poly1305 AEAD encryption module
✓ fix: reject transfer envelope with expired TTL
✓ docs: add threat model coverage for malicious browser extension
✓ feat(meissnerseal-core): add vault crash-safe write with fsync-rename strategy
✓ chore: initialize meissnerseal workspace

✗ feat: Complete development infrastructure design    ← capital letter, "Complete" not imperative
✗ feat: ADRs, CONTRACT files, spec update             ← no leading verb; reads as a list
✗ Add Tier 1 standards conformance                    ← no type prefix
✗ Fix stuff                                           ← not descriptive
✗ WIP                                                 ← never commit WIP to main
✗ feat: update things in crypto crate                 ← too vague
```

**Rules:**
- **Imperative mood** — "add", "fix", "remove", "update", "rename", not "added",
  "fixes", "removing".
- **No period** at the end of the subject line.
- **No capital letter** after the colon (the first word of the subject is lowercase
  unless it is a proper noun like `Key<N>` or `ML-KEM`).
- **50 characters ideal, 72 hard limit.** If you cannot describe the change in 72
  characters, split the commit or use a shorter description and expand in the body.
- **No "complete", "finish", "done", "WIP", "various changes"** — these describe
  your workflow state, not the change.

---

## 6. Body Rules

The body answers **why** the change was made and **what tradeoffs were considered**.
It does not repeat the subject or describe what the code does — the diff does that.

```
✓ Why this change:
  The vault format parser accepted trailing garbage after the last TLV frame.
  An attacker could embed arbitrary bytes after a valid vault and cause the
  parser to produce non-deterministic behavior across platforms.

✓ What was considered:
  Considered silently ignoring trailing bytes for forward compatibility.
  Rejected: unknown trailing bytes must be an error, not a tolerated condition.
  Fail-closed is the mandatory policy (AGENTS.md §4 PARSER invariants).

✗ What the code does:
  Changed the parse function to check for trailing bytes and return Err.
  Updated the test to cover the rejection case.
```

**Formatting rules:**
- Wrap at 72 characters per line.
- Blank line between subject and body.
- Blank line between paragraphs.
- Use Markdown-style bullet lists for multi-item content.
- Refer to spec files and ADRs by path when relevant:
  `See specs/protocol/vault_format_v1.md §6 for the rejection rule.`

---

## 7. Footer

Footer trailers are optional and separated from the body by a blank line.

Trailers:

| Trailer | Use |
|---|---|
| `Closes #N` | When the commit closes a GitHub issue |
| `Fixes #N` | When the commit fixes a bug tracked in an issue |
| `Refs #N` | When the commit is related to but does not close an issue |
| `BREAKING CHANGE: <description>` | When the commit changes a stable public API |

---

## 8. Atomic Commit Discipline

### One logical change per commit

A "logical change" is a change that can be described with a single type+subject.
If your subject requires "and" to be accurate, split the commit:

```
✗ feat: add HKDF module and fix nonce generation and update CONTRACT.md

✓ feat: add HKDF-SHA256 key derivation module
✓ fix: enforce fresh nonce generation for each AEAD seal call
✓ docs(meissnerseal-crypto): update CONTRACT.md for HKDF public API
```

### Exceptions

The following may be bundled in a single commit without splitting:

- A new module and its unit tests (inseparable)
- A new spec file and its corresponding ADR (inseparable documentation pair)
- A bug fix and its regression test (inseparable)
- A type alias rename across multiple files (one logical change, multiple files)

### What never belongs in a commit

- Unrelated formatting changes mixed with logic changes
- Commented-out code
- Debug print statements
- `todo!()` or `unimplemented!()` macros in code that is meant to be shipped
- Test fixtures containing real secret values, real seed phrases, or real API keys

---

## 9. When to Create a Commit

Agents must create a commit **only after**:

1. The task scope was declared (AGENTS.md §10)
2. Phase 1 (tests) was written and reviewed (if applicable per role)
3. The implementation passes all static tool checks:
   ```
   cargo fmt --all             — zero formatting errors
   cargo check --workspace     — zero type errors
   cargo clippy ... -D warnings — zero warnings
   cargo test --workspace      — zero test failures
   cargo audit                 — zero unresolved CVEs
   ```
4. The Completion Report (AGENTS.md §13) is ready

**Never commit:**
- When any of the above tools fail
- When tests are skipped or marked `#[ignore]` without a documented reason
- When `cargo audit` shows an unresolved CVE in a direct dependency
- When the commit would break the main branch build

---

## 10. Agent Completion Commit Template

Agents use this template to construct the commit body from their Completion Report:

```
<type>(<scope>): <imperative description of the primary change>

What changed:
- <list of files or modules changed, one line per item>
- <include the spec or ADR reference if applicable>

Why:
<One paragraph: the security requirement, invariant, or task that
motivated this change. Reference the relevant spec section or ADR.>

Verification:
- cargo fmt, check, clippy, test, audit: all pass
- Miri: <pass / not applicable — reason>
- Kani: <pass / not applicable — reason>
- Test vectors: <added / updated / not applicable>
```

**Filling in the template:**
- "What changed" describes files and modules, not code lines.
- "Why" is the security reasoning, not the technical description.
- "Verification" must be filled in honestly — never claim a tool passed if it
  was not run.

---

## 11. Commit History and Rewriting

### Local branches (not yet pushed)

History may be rewritten freely on local-only branches:
- `git commit --amend` to fix the most recent commit message
- `git rebase -i <parent>` to fix earlier commits

### After pushing to a shared remote

**Never rewrite history that has been pushed**, except:
- A security incident requires removing committed secret material
  (requires team coordinator approval)
- An explicit coordinated force-push on a feature branch that the team agreed to

### Main branch

Force-pushing to `main` is forbidden. No exceptions.

### Squashing

Squash only when the intermediate commits are genuinely "WIP checkpoints" with
no individual meaning. Do not squash commits that each represent a distinct
logical change — the log history is a project asset.

---

## 12. Security Constraints for Commits

These rules are absolute. Violations require immediate remediation including
history rewriting to remove the offending content.

```
FORBIDDEN in any commit message, body, or test fixture:
  Real secret values (passwords, seed phrases, API keys, tokens)
  Real private keys (SSH, GPG, X25519, ML-KEM)
  Internal server addresses, credentials, or database URLs
  Real vault files or real .msexp bundles
  Personal identifying information of users

REQUIRED:
  Test vectors use generated dummy data, not real secrets
  Error messages in test assertions must not reproduce secret values
  Commit bodies reference spec paths, not internal deployment details
```

---

## 13. Branch Strategy

```
main                    — always deployable, protected
  ↑
  feat/<ticket>-<desc>  — agent feature branches (one per task)
  fix/<ticket>-<desc>   — agent fix branches
  docs/<desc>           — documentation-only branches
```

**Naming convention:**
- `feat/mvp0-kdf-argon2id` — MVP phase + module + what
- `fix/aead-nonce-freshness` — area + what
- `docs/adr-017-replay-window` — type + identifier

**Merge strategy:**
- Squash merge for single-commit feature branches
- Merge commit (no squash) for multi-commit feature branches where
  the commit history has independent value
- Never merge directly to main without CI passing and human review

**Doc/spec fixes during feature PR review:**
- Do NOT add doc/spec-only commits to an open feature branch — this triggers
  a full CI re-run (Miri ~60 min, Fuzz ~2 min) on a Rust-free change.
- Open a separate `docs/<desc>` branch instead. `docs/` branches only require
  `ci-fast` (~5 min); `ci-thorough` is not needed for documentation changes.

---

## 14. Pull Request Description Standard

### Mandatory (all PRs)

```
## Summary
- Bullet list of what changed and why (imperative, technical)
```

### Code PRs (feat / fix / security / ci) — add as applicable

```
## Verification
- Agent review results (Consistency/Security/Formal Review Agent outcome)
- ProVerif / Kani / Miri results with counts where relevant
- CI: N/N checks pass

## ADRs                    ← include when PR references or adds ADRs
- ADR-NNN: <title> (new / updated / cross-referenced)

## Spec authority          ← include when implementation is spec-driven
<spec files and sections that govern this change>

## Findings                ← include when findings are raised or closed
| ID | Severity | Kind | Status |
|---|---|---|---|
| F-NN | Critical/High/Medium/Low | <description> | Resolved / Deferred / Accepted |
```

### Docs PRs (docs/)

`## Summary` is sufficient. No Verification, ADRs, or Findings sections needed.

### Rules

- No `## Test plan` — tests must pass before the PR is opened; write results, not intentions
- No `## Merge note` — merge procedure is in AGENTS.md §14, not the PR body
- Findings table uses `| ID | Severity | Kind | Status |` format; omit section if no findings

---

## 15. Practical Reference — Common Mistakes

| Mistake | Correct form |
|---|---|
| `feat: added HKDF support` | `feat: add HKDF-SHA256 key derivation` |
| `fix: Fixed the bug` | `fix: reject transfer envelope with expired TTL` |
| `docs: Update docs` | `docs: add KDF cross-verification guide` |
| `feat: complete MVP-0 task` | Split into the actual changes made |
| `WIP: crypto` | Never commit WIP to main; use a branch |
| `feat: HKDF and fix nonce and update spec` | Three separate commits |
| Missing type prefix | Always prefix: `feat:`, `fix:`, `docs:`, etc. |
| Subject ends with period | Remove the period |
| Body repeats the subject | Body explains WHY, not WHAT |
