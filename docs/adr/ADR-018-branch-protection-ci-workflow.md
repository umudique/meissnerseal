# ADR-018: Branch Protection and CI Workflow Strategy

**Status:** Accepted
**Date:** 2026-06-06
**Related:** ADR-017 (extended toolchain), AGENTS.md §14

---

## Context

With GitHub connected and CI operational, the project needed a policy for:

1. **Which commits trigger CI** — running CI on every branch push wastes
   minutes and creates noise before code is ready for review.
2. **What gates a merge to `main`** — `main` must always be in a
   deployable, CI-green state. Informal merge discipline is not sufficient.
3. **PR review requirement** — the project has a single developer.
   Requiring a reviewer makes merging impossible without a workaround.
4. **History integrity** — force-push to `main` must be forbidden once
   the remote is established, to prevent accidental or tooling-induced
   history rewrites reaching the shared ref.
5. **Verification drift** — GitHub branch protection is configured through
   the UI or API; it can silently drift. Decisions made here must be
   machine-verifiable.

---

## Decision

### Branch protection rules for `main`

| Rule | Value | Rationale |
|---|---|---|
| Required status checks | `Format`, `Check`, `Clippy`, `Test`, `Audit`, `Deny` | The six ci-fast jobs are the minimum bar for a correct, safe commit |
| Strict status checks | `true` | Branch must be up-to-date with `main` before merge |
| Required PR reviews | 0 (none) | Single developer; review requirement is unenforceable and blocks self-merge |
| Dismiss stale reviews | n/a (reviews not required) | — |
| Required signatures | `true` | All commits on `main` must be signed; SSH signing via `~/.ssh/id_rsa.pub` |
| Required linear history | `true` | Merge commits forbidden; PRs must be rebased or squashed — keeps `git bisect` reliable |
| Enforce admins | `false` | Allows emergency direct push when CI is broken at the infra level |
| Allow force pushes | `false` | Protects shared history; force push requires explicit temporary unlock |
| Allow deletions | `false` | — |
| Conversation resolution | `true` | PR threads must be resolved before merge |

### CI trigger strategy

| Workflow | Trigger | Rationale |
|---|---|---|
| `ci-fast.yml` | `push: main`, `pull_request: main` | Status-check jobs must run on PRs; push-to-main catch post-merge regressions |
| `ci-thorough.yml` | `pull_request: main`, nightly schedule | Slow jobs (Miri, coverage, SBOM) run at merge gate and nightly |
| `security-scan.yml` | `push: main`, `pull_request: main` | Gitleaks and semgrep run at merge gate; main-push catches anything that bypassed |
| `codeql.yml` | `push: main`, weekly schedule | CodeQL is too slow for PR-level; catches regressions on main and weekly |

**Not triggered on `dev` or feature branch pushes.** Work accumulates locally
with pre-commit enforcement; CI runs once when a PR is opened.

### Daily workflow

```
local commits on dev  →  pre-commit hook (fmt / check / clippy / deny / audit)
gün sonu push         →  git push origin dev
PR dev → main         →  CI runs (ci-fast + ci-thorough + security-scan)
all 6 checks green    →  self-merge (no reviewer required)
post-merge            →  codeql runs on main
```

### Verification

`scripts/verify-github-config.sh` checks the live GitHub API against the
expected values defined in this ADR. Run manually or add to a periodic
check. Exits non-zero on any drift.

---

## Alternatives Considered

**Require 1 PR reviewer (self-approve):**
GitHub does not allow a PR author to approve their own PR unless
`allow_self_review` is explicitly enabled. This creates a dead-end for
solo work. Removed in favour of 0 required reviews with mandatory CI.

**CI on all branch pushes:**
Wastes CI minutes on work-in-progress commits. The pre-commit hook
provides the same fast-feedback loop locally without consuming GitHub
Actions quota.

**Terraform GitHub provider for IaC:**
Correct long-term direction but introduces Terraform state management
overhead that is disproportionate at this project phase. The verification
script covers drift detection until team size warrants full IaC.

**`enforce_admins: true`:**
Would prevent the single developer from bypassing CI even in emergencies
(e.g., broken CI infra blocking a security patch). Deferred until a
second developer joins.

**Hardened CI runner model:**
GitHub-hosted runners already provide ephemeral VMs, managed images, and job
isolation — equivalent to the core properties of self-hosted ephemeral runners.
Additional hardening (locked runner image, restricted network egress, privileged
container controls, custom artifact retention) becomes meaningful when: (a) the
threat model explicitly includes CI runner compromise, (b) a managed sync
service handles payment data, or (c) an external security audit requires it.
Deferred to MVP-5 (Managed Sync Beta), when runner security aligns with the
broader operational security review.

---

## Consequences

- Every merge to `main` is CI-green by construction.
- Dev branch pushes generate zero CI cost.
- Branch protection configuration is auditable via `scripts/verify-github-config.sh`.
- Force-push to `main` requires a deliberate, two-step unlock (Settings → enable → push → disable).
- When a second developer joins: re-enable `required_pull_request_reviews: 1`
  and consider `enforce_admins: true`.
