<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-033 — Vault Typestate Model

**Status:** Accepted  
**Date:** 2026-06-11  
**Related:** ADR-015 (mathematical verification), ADR-023 (libcrux ML-KEM backend),
             ADR-032 (version policy)

---

## Context

The current meissnerseal-core vault API uses two separate types to represent vault
state:

```rust
pub struct VaultHandle { ... }   // locked — path only, no keys
pub struct VaultSession { ... }  // unlocked — holds UnlockedKeys
```

`create()` returns `VaultHandle`. `unlock()` consumes a `VaultHandle` and
returns `VaultSession`. Item operations take `&VaultSession`.

This works at runtime but has a structural weakness: the locked/unlocked
distinction is enforced by convention, not by the type system. A caller holding
a `VaultHandle` cannot call item operations — but this is because no such API
exists, not because the compiler prevents it. As the API surface grows (MVP-2
transfer, MVP-3 sync), new callers and new operations increase the risk that
an operation is wired to the wrong state type, or that a future refactor
accidentally exposes a path that bypasses the unlock check.

The typestate pattern encodes state transitions directly into the type
signature. Impossible states become compile errors.

MVP-2 will add transfer and device-identity operations that require unlocked
vault access. This is the last point at which the API can be restructured
without breaking a growing set of callers.

---

## Decision

Replace `VaultHandle` + `VaultSession` with a single `Vault<S>` type
parameterised over a state marker:

```rust
pub struct Locked;
pub struct Unlocked;

pub struct Vault<S> {
    path: PathBuf,
    state: PhantomData<S>,
    // keys present only when S = Unlocked
}
```

State transitions are the only way to move between states:

```rust
impl Vault<Locked> {
    pub fn create(params: CreateVaultParams) -> Result<Vault<Locked>>;
    pub fn open(path: &Path) -> Result<Vault<Locked>>;
    pub fn unlock(self, password: &[u8]) -> Result<Vault<Unlocked>>;
}

impl Vault<Unlocked> {
    pub fn lock(self) -> Vault<Locked>;
}
```

Item operations, export/import, and transfer operations are implemented
exclusively on `Vault<Unlocked>`. They are not accessible on `Vault<Locked>`
— not by convention but by the type system.

---

## Alternatives Considered

### Keep current VaultHandle + VaultSession

Rejected. The two-type model works now but does not scale. Every new operation
must be wired to the correct type manually. As MVP-2 and MVP-3 add callers,
this becomes a maintenance and audit burden. The typestate costs one refactor
now and pays forward indefinitely.

### Runtime lock-check guard

```rust
fn ensure_unlocked(&self) -> Result<&UnlockedKeys> { ... }
```

Rejected. Runtime checks are fallible — they can be forgotten, bypassed, or
elided under refactoring. A typestate check is not a runtime path; it does
not exist at runtime. The compiler enforces it unconditionally.

### Session token / capability model

Pass an opaque `SessionToken` to operations instead of holding state in the
vault type. Rejected: indirection without benefit. The typestate achieves the
same capability restriction with less complexity and no runtime cost.

---

## Consequences

- `meissnerseal-core` public API is a breaking change. All callers
  (`meissnerseal-cli`, future `meissnerseal-ffi`, `meissnerseal-sync-server`) must be updated.
- The `Vault<Unlocked>` type becomes the single locus for secret key material.
  `UnlockedKeys` is an implementation detail, not part of the public API.
- Kani harnesses can assert state transition invariants at the type level:
  `Vault<Locked>` has no key material, `Vault<Unlocked>` has exactly one set.
- Canary E2E tests (TOOL-4) verify that no secret material appears in output
  produced by `Vault<Locked>` operations — a complement to the type-level
  guarantee.
- Implementation milestone: before MVP-2 kickoff. The transfer layer will be
  built against `Vault<S>` from the start; retrofitting after MVP-2 callers
  exist is significantly more expensive.
