<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-019: Base Development Toolchain

**Status:** Accepted  
**Date:** 2026-06-06  
**Related:** ADR-017 (extended toolchain), ADR-015 (mathematical verification),
             ADR-018 (branch protection and CI workflow)

---

## Context

MeissnerSeal is a security-critical Rust project. The toolchain must enforce a
minimum correctness and safety bar on every commit, locally and in CI, before
any code reaches `main`. The base toolchain covers:

- Code formatting and style consistency
- Compile-time correctness (all targets, all features)
- Lint discipline (warnings treated as errors)
- License and dependency policy enforcement
- Known vulnerability scanning
- Pre-commit hook wiring

This ADR records the initial toolchain selected at project inception, which
ADR-017 later extended with security scanning, supply-chain, and quality tools.

---

## Decision

### Formatting — `rustfmt`

**Adopted.** Zero-configuration formatting via `cargo fmt --all`. Enforced in
CI (`fmt` job) and pre-commit. Non-negotiable: formatting disagreements are a
distraction in a security-focused codebase.

### Lint — `clippy`

**Adopted.** `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
All warnings promoted to errors. Clippy catches a wide class of correctness
issues (integer overflow, unchecked indexing, suspicious patterns) that rustc
does not flag.

Workspace lint configuration:

```toml
# Cargo.toml (workspace root)
[workspace.lints.rust]
unsafe_code = "warn"
dead_code = "warn"
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(kani)', 'cfg(prusti)'] }
```

Each crate opts in with `[lints] workspace = true`. This ensures lint
inheritance is explicit and auditable, not implicit.

### Compile check — `cargo check`

**Adopted.** `cargo check --workspace --all-targets` runs before clippy in the
pre-commit hook to produce faster error messages on compilation failures.

### License and dependency policy — `cargo-deny`

**Adopted.** Enforces:
- License allow-list (MIT, Apache-2.0, ISC, BSD-2/3-Clause, etc. — see deny.toml)
- Advisory database checks (yanked crates, known CVEs)
- Unmaintained and unsound crate detection

Schema version 2 (cargo-deny ≥ 0.14). Configuration in `deny.toml`.
Internal workspace crates versioned in `[workspace.dependencies]` to avoid
wildcard warnings.

### Vulnerability scanning — `cargo-audit`

**Adopted.** Queries the RustSec advisory database for known CVEs in the
dependency tree. Runs as the final pre-commit stage and in CI.

Relationship to `cargo-deny`: cargo-deny covers license policy, bans, and
advisory checks holistically; cargo-audit provides a focused CVE-only view
and a simpler failure signal in the pre-commit hook.

### Unsafe code tracking — `cargo-geiger`

**Adopted** for periodic manual review. Not in CI or pre-commit (output is
informational, not pass/fail). Provides a count of `unsafe` blocks per
dependency to guide dependency selection and review prioritisation.

### Pre-commit hook

**Adopted.** `.githooks/pre-commit` runs six stages in order:

| Stage | Tool | Purpose | Target time |
|---|---|---|---|
| 1 | gitleaks | Secret detection | ~1 s |
| 2 | rustfmt | Format check | ~2 s |
| 3 | cargo check | Compile check | ~5 s |
| 4 | clippy | Lint | ~8 s |
| 5 | cargo-deny | License + policy | ~2 s |
| 6 | cargo-audit | CVE scan | ~5 s |

Installed via `git config core.hooksPath .githooks` (run `scripts/setup-dev.sh`).
Target total: < 30 seconds. Miri, tests, fuzzing, and coverage run in CI only.

### CI pipeline — `ci-fast.yml`

**Adopted.** Mirrors the pre-commit hook as six independent parallel jobs
(`fmt`, `check`, `clippy`, `test`, `audit`, `deny`). All six are required
status checks on `main` (ADR-018). Runs on PRs targeting `main` and on
direct pushes to `main`.

---

## Alternatives Considered

**`cargo test` in pre-commit:**  
Rejected. Test suite runtime exceeds the 30-second pre-commit budget. Tests
run in CI (`test` job with cargo-nextest). Fast unit tests may be added to
pre-commit in future if the suite remains under budget.

**Single monolithic CI job:**  
Rejected. Parallel jobs provide faster feedback (each job ~2–3 min) and
isolate failure signals. A format error should not require waiting for clippy.

**`deny.toml` version 1 schema:**  
Rejected. cargo-deny ≥ 0.14 removed several version-1 fields. Version 2
schema used from the start.

**Implicit lint inheritance (no `[lints] workspace = true`):**  
Rejected. Without explicit opt-in per crate, workspace lint configuration has
no effect. Each crate must declare `[lints] workspace = true`.

---

## Consequences

- Every commit to `main` has passed: format, compile, clippy -D warnings,
  license policy, and CVE scan.
- Unsafe code usage is tracked (geiger) and attributable in git history.
- The pre-commit hook provides the same bar locally, catching issues before
  they reach CI.
- ADR-017 extended this baseline with gitleaks, CodeQL, semgrep,
  cargo-auditable, syft, cargo-nextest, cargo-llvm-cov, and cargo-machete.
