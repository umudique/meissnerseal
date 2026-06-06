# ADR-017: Extended Toolchain — Security Scanning, Quality, and Supply Chain

**Status:** Accepted
**Date:** 2026-06-06
**Related:** ADR-015 (mathematical verification), ADR-016 (standards conformance),
             security_engineering_protocol.md

---

## Context

The initial toolchain (ADR-015, ADR-016) covered the core Rust quality and
mathematical verification layers. As the repository is now on GitHub with CI,
additional tools become feasible at near-zero marginal cost. The question is
which tools add genuine security or quality assurance, and which are ceremony.

Evaluation criteria applied to each candidate:
1. Does it catch a class of bugs or risks the existing tools miss?
2. Is the signal-to-noise ratio acceptable?
3. Is the setup and maintenance cost proportionate?
4. Does it fit the current project phase (pre-MVP-0)?

---

## Decision

### Adopted Now

**gitleaks** — secret scanning on staged commits and git history
- Rationale: A secrets vault project that leaks secrets into its own commit
  history is a category error. gitleaks detects high-entropy strings, API key
  patterns, and known secret formats before they are committed.
- Integration: pre-commit hook (staged files) + CI (full history on PR)

**CodeQL** — GitHub's static analysis (security and correctness queries)
- Rationale: Free for private repos on GitHub. Rust support added 2024. Finds
  memory patterns, logic errors, and injection paths that clippy misses.
  Runs on a schedule; slow but high signal.
- Integration: `.github/workflows/codeql.yml`, weekly + main push

**CODEOWNERS** — mandatory human review for critical files
- Rationale: Enforces the human gate on cryptographic code, specs, ADRs, and
  CI/supply chain configuration. Agents cannot approve their own PRs to these
  paths.
- Integration: `.github/CODEOWNERS`

**shellcheck** — static analysis for shell scripts
- Rationale: `scripts/setup-dev.sh` and `.githooks/pre-commit` are
  security-relevant (they control what runs before each commit). A subtle bash
  bug can silently skip a security check. shellcheck catches these.
- Integration: ci-fast.yml job + local via setup-dev.sh

**cargo-auditable** — embed dependency manifest in release binaries
- Rationale: Post-incident: "which version of X was in that binary?"
  cargo-auditable embeds a compressed Cargo.lock into the binary. Enables
  `cargo audit bin` to scan deployed artifacts. Near-zero build cost.
- Integration: `cargo auditable build` replaces `cargo build` in provenance job

**syft** — SBOM generation (CycloneDX / SPDX)
- Rationale: SBOM is a Beta release gate (security_assurance.md §6). Adding
  the CI job now costs nothing and produces useful artifacts.
- Integration: ci-thorough.yml job, CycloneDX JSON output

**cargo-machete** — unused dependency detection
- Rationale: Unused dependencies expand the supply chain attack surface.
  cargo-machete finds Cargo.toml entries that are imported but not referenced.
  Fast, zero false-positive rate in practice.
- Integration: ci-fast.yml job

**yamllint** — YAML linting for CI workflow files
- Rationale: A malformed CI workflow silently degrades security gates. GitHub
  Actions errors can go unnoticed. yamllint catches syntax and style errors.
- Integration: ci-fast.yml job

**cargo-nextest** — faster test runner with per-test timeouts
- Rationale: Replaces `cargo test` with parallel execution and per-test
  timeouts. A hanging test no longer blocks the full suite. Faster CI.
  Doctests require a separate `cargo test --doc` step.
- Integration: ci-fast.yml (replaces test job)

**Dependabot** — automated dependency update PRs
- Rationale: cargo-audit catches known CVEs reactively. Dependabot proactively
  opens PRs when new versions appear, including security patches.
  Complements, does not replace, cargo-audit.
- Integration: `.github/dependabot.yml`, weekly schedule

**semgrep** — semantic code pattern analysis
- Rationale: Custom rules can encode Arcanum-specific invariants that clippy
  cannot express: "no direct rand call outside the rng module", "no
  PartialEq on types implementing ZeroizeOnDrop". Rust security ruleset
  catches common misuse patterns.
- Integration: `.github/workflows/security-scan.yml`

**cargo-llvm-cov** — LLVM-based coverage measurement
- Rationale: Without coverage data, there is no way to know if the crypto
  test suite exercises error paths and edge cases. Coverage does not
  guarantee quality, but missing coverage guarantees a gap.
- Integration: ci-thorough.yml job, LCOV report as artifact

### Deferred to Beta

**cargo-mutants** — mutation testing
- Rationale: Mutation testing is the strongest test quality signal available:
  it verifies that removing or mutating code causes tests to fail. For
  cryptographic functions, this is very valuable.
- Why deferred: Requires a full implementation to mutate. Pre-MVP-0, the
  codebase is mostly stubs. Add at MVP-0 completion.
- Milestone: MVP-0 complete → run cargo-mutants on arcanum-crypto

**cargo-semver-checks** — semver compatibility verification
- Rationale: Detects breaking API changes that are not reflected in version
  bumps. Prevents silent API breakage in downstream users.
- Why deferred: All crates are `API Status: Unstable`. Semver-checking an
  unstable API is undefined. Add when first crate reaches Stable.
- Milestone: First `API Status: Stable` promotion → add cargo-semver-checks

### Excluded

| Tool | Reason |
|---|---|
| trufflehog | gitleaks covers the same class; duplicate signal |
| typos | Low value relative to maintenance cost |
| taplo | TOML formatting; cargo fmt covers Rust files, Cargo.toml divergence is minor |
| markdownlint | Documentation style; not a security signal |
| shfmt | shellcheck sufficient; formatting does not affect correctness |
| cargo-msrv | No minimum Rust version target; always latest stable |

---

## Consequences

### Layer additions to security_engineering_protocol.md

The tool inventory gains three new layers:

- Layer 10 — Secret scanning (gitleaks, pre-commit + CI)
- Layer 11 — Semantic analysis (CodeQL, semgrep)
- Layer 12 — Supply chain artifacts (cargo-auditable, syft SBOM)

### Process additions

- CODEOWNERS enforces human review gate for crypto/ and specs/ on every PR
- Dependabot PRs require the same CI gate as any other PR before merge
- cargo-mutants is a manual milestone gate, not a CI blocker

### Maintenance cost

Each added tool is a CI job or a config file. The net addition is:
- ci-fast.yml: +3 jobs (yamllint, shellcheck, machete)
- ci-thorough.yml: +2 jobs (syft, llvm-cov)
- New workflows: codeql.yml, security-scan.yml
- Config files: CODEOWNERS, dependabot.yml, .yamllint.yml
