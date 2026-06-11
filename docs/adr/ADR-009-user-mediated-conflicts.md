<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-009: User-Mediated Conflict Resolution for Critical Secrets

**Date:** 2025-06
**Status:** Accepted

## Context

When two devices concurrently edit the same vault item and neither version vector
dominates the other, Arcanum must resolve the conflict. Auto-merge strategies must
be evaluated against the critical-secret use case.

## Decision

Last-write-wins is forbidden for critical secret payloads.
Conflicting revisions are preserved and the user is asked to choose.

Critical types that must never be auto-merged:
- SeedPhrase
- SigningKey
- SshPrivateKey
- ApiToken
- RecoveryCode

## Rationale

- A seed phrase silently merged or overwritten is catastrophic and unrecoverable
- "Data loss is better than data corruption" applies: keeping both versions and
  asking the user is always recoverable; silent LWW is not
- Metadata-only conflicts (labels, timestamps) may support guided merge in future;
  MVP preserves both versions

## Consequences

- Sync Protocol must detect concurrent edits via version vectors
- UI must present conflict UI for all types in MVP
- Conflict evidence must not be deleted from the local change journal until resolved
- TLA+ model must verify that conflicting versions are never silently discarded
