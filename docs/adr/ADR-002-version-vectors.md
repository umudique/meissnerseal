<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-002: Version Vectors for Sync Conflict Detection

**Date:** 2025-06
**Status:** Accepted

## Context

Multi-device encrypted sync requires a concurrency model to detect and represent
conflicting edits without losing data.

## Alternatives Considered

1. **Monotonic revision IDs (server-assigned):** simple, but cannot detect concurrent
   edits; last-write-wins is the only resolution — unsafe for critical secrets.
2. **Vector clocks / version vectors:** each device has its own counter; concurrent
   edits are detectable; requires more storage and client-side logic.
3. **CRDTs:** too complex for critical secret types; auto-merge semantics are unsafe
   for seed phrases and signing keys.

## Decision

Client-side version vectors (`Map<DeviceId, Counter>`).
The server maintains a monotonic commit index for ordering and pagination only.

## Rationale

- Concurrent edits are detectable: neither vector dominates → conflict
- No auto-merge for critical items (SeedPhrase, SshPrivateKey, ApiToken, etc.)
- Server remains zero-knowledge: it sees blob metadata, not conflict semantics
- TLA+ model can verify the conflict detection and tombstone propagation

## Consequences

- Each device maintains a version vector, incremented on local edits
- Conflict resolution is user-mediated for critical secret types
- Tombstones required for deletes; retained for offline device support window
- Version vector pruning policy required for revoked devices (90-day minimum)
- TLA+ model required before MVP-3 public preview
