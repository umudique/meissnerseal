<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-034 — Local CI as Primary Gate

**Status:** Accepted  
**Date:** 2026-06-11  
**Related:** .pre-commit-config, ops/AGENTS.md

---

## Context

GitHub Actions free-tier imposes monthly minute limits. MeissnerSeal's CI suite
(secrets scan, fmt, check, clippy, deny, audit, nextest, Miri, fuzzing) is
compute-intensive; running it on every push risks exhausting the quota and
blocking merges mid-milestone.

---

## Decision

The same checks that would run on GitHub CI are enforced locally:

- **Pre-commit hook** (`.pre-commit-config` / `ops/scripts/pre-commit`) runs on
  every `git commit`: secrets, fmt, check, clippy, deny, audit.
- **Full suite** (`cargo nextest run --workspace`, Miri, fuzz targets) is run
  manually before tagging a release or merging a gate branch.

GitHub Actions remains configured but is treated as a secondary signal, not the
primary gate. A failed remote CI job does not block local development.

---

## Consequences

- Development is never blocked by GitHub quota.
- CI parity is maintained: the local hook mirrors the remote workflow exactly.
- The pre-commit hook must stay in sync with any future changes to the remote
  workflow definition.
