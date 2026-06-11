<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-021: CodeQL Deferred — Private Repository Constraint

**Status:** Accepted  
**Date:** 2026-06-06  
**Related:** ADR-017 (extended toolchain), ADR-018 (CI workflow strategy)

---

## Context

The extended toolchain (ADR-017) includes CodeQL semantic analysis as a
security scanning layer. The codeql.yml workflow was implemented and
SHA-pinned as part of the CI hardening effort.

When the workflow was triggered on the private repository, it failed with:

```
Code scanning is not enabled for this repository. Please enable code
scanning in the repository settings.
```

Investigation confirmed that CodeQL Code Scanning (SARIF upload to GitHub
Security tab) requires **GitHub Advanced Security (GHAS)**, which is only
available with GitHub Enterprise plans. GitHub Pro for individual accounts
does not include GHAS for private repositories.

---

## Decision

Disable automatic CodeQL triggers (`push`, `schedule`) until one of the
enabling conditions below is met. The workflow file is retained and the
trigger is set to `workflow_dispatch` (manual-only) so the analysis can
still be run on demand if needed.

**Enabling conditions (any one sufficient):**

1. Repository is made public — Code Scanning is free for all public repos
2. GitHub Enterprise plan is adopted — GHAS included
3. GitHub expands Code Scanning to Pro plan private repos

---

## Alternatives Considered

**Remove CodeQL workflow entirely:**  
Rejected. The workflow represents intent and tooling investment. Keeping it
as manual-only preserves the option without the daily failure noise.

**`continue-on-error: true` on the analyze job:**  
Rejected. This would run CodeQL on every push, consume Actions minutes,
and silently fail — worse than not running at all.

**Self-hosted CodeQL CLI:**  
Possible but requires infrastructure and the SARIF upload still requires
GHAS. Deferred to the same milestone as GHAS adoption.

---

## Consequences

- CodeQL does not run on push or schedule for the private repository.
- Static analysis gap is partially covered by `semgrep` (security-scan.yml)
  which runs on every PR and does not require GHAS.
- When the repository is made public or GHAS is available, restore the
  trigger by replacing `workflow_dispatch` with the original `push`/`schedule`
  triggers in `.github/workflows/codeql.yml`.
