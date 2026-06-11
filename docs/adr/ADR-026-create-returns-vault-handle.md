<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-026: create Returns VaultHandle, Sessions Only via unlock

**Status:** Accepted  
**Date:** 2026-06-08  
**Related:** ADR-020 (agent governance / API Stable is a human gate),
ADR-025 (core Stable by implementation, not re-scoping), meissnerseal-core
CONTRACT P-01, finding_register F-11

---

## Context

The meissnerseal-core contract already declares:

```text
vault::
  create(params: CreateVaultParams) -> Result<VaultHandle>
  unlock(path, master_secret) -> Result<VaultSession>
```

CONTRACT P-01 also states that `VaultSession` must be obtained through
`vault::unlock` only. Before F-11 was resolved, the implementation contradicted
that contract: `create()` derived the key hierarchy, persisted the vault, and
returned a live `VaultSession`.

That contradiction weakens the lifecycle boundary. A freshly-created vault file
should be locked until the caller explicitly unlocks it, so the same
authentication, policy, hardware re-auth, and session-audit path is used for
every live session.

ADR-025 already decided the project resolves core Stable-readiness findings by
implementing the contract rather than re-scoping the contract downward. F-11 is
one of those code-to-contract findings.

---

## Decision

`vault::create()` returns a locked `VaultHandle`, not a live `VaultSession`.

`VaultSession` is obtainable only through `vault::unlock()`, as required by
CONTRACT P-01.

During creation, meissnerseal-core may derive the key hierarchy only long enough to
wrap and persist the `VaultRootKey`. Those derived keys are not placed in any
returned value and are dropped before `create()` returns. The returned
`VaultHandle` contains no key material; it identifies the persisted vault file
that can later be opened with `unlock()`.

Rationale:

- **Single session-birth chokepoint:** sync, transfer, device, and recovery
  layers can rely on one entry point for live session creation.
- **Future hardware re-auth mount point:** enclave or biometric re-auth can be
  attached to `unlock()` without needing a parallel path in `create()`.
- **Write-verify:** the first live session after creation requires reading the
  persisted vault back through `unlock()`, proving the file round-trips.
- **Least live key material:** creation does not leave a live session or keys
  resident after the vault is persisted.

---

## Alternatives Considered

**Relax P-01 and return `VaultSession` from `create()`:**  
Rejected. It preserves the old implementation shape but splits session birth
across two APIs. That would complicate future policy, sync, transfer, device,
recovery, and hardware re-auth controls and would make `create()` a second path
that leaves live key material resident.

**Keep returning both handle and session:**  
Rejected for the same reason. The handle is non-secret routing metadata; the
session is live key material. Returning both would still violate the intent of
P-01.

---

## Consequences

- Callers that want to use a newly-created vault must call `unlock()` after
  `create()`.
- `create()` must remain responsible for crash-safe persistence and
  WrappedRootKey creation, but it must not expose the derived session keys.
- Tests must assert that creation yields a handle and that any usable
  `VaultSession` comes from `unlock()`.
- This decision resolves F-11 in the implementation direction selected by
  ADR-025; it does not mark meissnerseal-core Stable. Stable remains a separate
  human gate under ADR-020.
