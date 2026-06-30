<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-040: Zeroization Verification Strategy

**Status:** Accepted  
**Date:** 2026-06-30  
**Related:** F-72 (docs/security/finding_register.yaml),
             crates/meissnerseal-security/src/secret_lifecycle.rs,
             crates/meissnerseal-crypto/src/types.rs,
             docs/security/security_engineering_protocol.md

---

## Context

MeissnerSeal wraps all secret material in `ZeroizeOnDrop` types
(`SecretBytes`, `SecretString`, `Key<N>`) so that the backing memory is
cleared when a value is dropped. This is a core security property: a
process crash, a core dump, or a memory scan after vault lock must not
expose plaintext secrets.

The existing unit test `test_secret_bytes_zeroize` in
`secret_lifecycle.rs` is a no-op: it obtains a raw pointer to the
buffer before drop and discards it with `let _ = ptr` without reading
the memory afterwards. The test passes unconditionally and provides no
evidence that zeroization actually occurs (F-72).

Two distinct verification problems must be solved:

**Problem 1 — Compiler elimination.** The compiler may remove writes to
memory that it determines are "dead" (no subsequent read). The `zeroize`
crate addresses this with `volatile_write` + `compiler_fence(SeqCst)`.
Miri, operating at the MIR level, can detect whether these volatile
writes are present and whether a value is zeroed before its memory is
reused.

**Problem 2 — Runtime evidence.** A test that actually reads the backing
buffer after drop and asserts all bytes are zero gives human-readable
evidence that the `ZeroizeOnDrop` derive is present and not accidentally
removed. This is the gap F-72 identifies.

---

## Decision

### 1. Primary verification: ManuallyDrop + raw pointer read

For heap-allocated types (`SecretBytes`, `SecretString`), tests use
`std::mem::ManuallyDrop` to prevent the allocator from freeing the
backing buffer before the assertion:

```rust
let mut s = ManuallyDrop::new(SecretBytes::new(vec![0xAA_u8; 32]));
let (ptr, len) = s.with_secret(|b| (b.as_ptr(), b.len()));

// Trigger ZeroizeOnDrop without running Vec::drop (no deallocation).
unsafe { ManuallyDrop::drop(&mut s); }

// Buffer is zeroed but not yet freed — read is safe relative to the
// allocator, though technically UB per the Rust abstract machine.
// Accepted: this is test-only code that never ships in a release
// binary, and the allocator on all target platforms does not overwrite
// freed memory before the next allocation.
let after = unsafe { std::slice::from_raw_parts(ptr, len) };
assert!(after.iter().all(|&b| b == 0), "SecretBytes must zero on drop");
```

This pattern is used by the `zeroize` crate's own test suite and by
multiple audited Rust security libraries. The trade-off is accepted:

- **UB exposure:** Reading memory after `ManuallyDrop::drop` is
  undefined behaviour under the Rust abstract machine because the
  value's lifetime has ended. On all supported platforms the allocator
  does not overwrite freed blocks immediately, so the read is safe in
  practice.
- **Scope:** Test-only (`#[cfg(test)]` or `tests/`). No production
  binary is affected.
- **Mitigation:** The same property is independently verified by Miri
  (Problem 1 above), which does not require the UB read and confirms
  the volatile write is not optimised away.

### 2. Miri as compiler-level co-verifier

`cargo +nightly miri test -p meissnerseal-security` is already in the
toolchain checks for this crate. Miri tracks volatile writes and will
flag if a `ZeroizeOnDrop` zeroing sequence is missing or if the memory
is read after drop in the production path. The ManuallyDrop test and
Miri together provide defence in depth: one confirms runtime behaviour,
the other confirms compiler-level correctness.

### 3. Coverage scope

The following types require zeroization tests under this strategy:

| Type | Crate | Heap/Stack |
|---|---|---|
| `SecretBytes` | meissnerseal-security | Heap (`Vec<u8>`) |
| `SecretString` | meissnerseal-security | Heap (`String`) |
| `Key<N>` | meissnerseal-crypto | Stack (`[u8; N]`) |

For stack-allocated `Key<N>`, `ManuallyDrop` prevents the stack slot
from being reclaimed; a raw pointer read after drop verifies zeroing
in the same way.

### 4. What this strategy does not verify

- **Swap/core dump exposure.** If the OS swaps secret pages to disk
  before zeroization, zeroization on drop does not help. `mlock(2)`
  addresses this; it is tracked as a separate open item and deferred
  past MVP-2.
- **CPU register/cache residue.** Clearing SIMD registers that held
  secret bytes requires platform-specific intrinsics. Out of scope for
  MVP-2.
- **Compiler cross-function optimisation.** LTO could theoretically
  eliminate a zeroing write visible across crate boundaries. The
  `volatile_write` in `zeroize` prevents this; Miri confirms it per
  compilation unit.

---

## Alternatives Considered

**Trust the `zeroize` crate without any runtime test.** The crate is
well-audited and uses `volatile_write`. However, a derive accidentally
removed during refactor would be silently undetected. Rejected: the
cost of the test is low, the cost of silent regression is high.

**Valgrind Memcheck.** Can track heap contents after deallocation.
Requires a suppression file for Rust's allocator (significant false
positive rate), runs very slowly with Argon2id allocations, and is not
in the existing CI toolchain. Rejected in favour of the simpler
ManuallyDrop approach; may be revisited for FFI boundary verification.

**Custom allocator that records last-written bytes at deallocation.**
Would eliminate the UB objection entirely. Significant implementation
complexity for a test-only concern. Rejected for MVP-2.

**Address Sanitizer (`-Z sanitizer=address`).** Detects use-after-free
but does not assert that freed memory contains zeros. Does not satisfy
the verification requirement.

---

## Consequences

- `test_secret_bytes_zeroize` in `secret_lifecycle.rs` is replaced with
  a ManuallyDrop + raw pointer test that asserts all bytes are zero.
- Equivalent tests are added for `SecretString` and `Key<N>`.
- The test-only UB trade-off is documented here and in a `// SAFETY:`
  comment on every `unsafe` block in the test.
- `mlock(2)` and swap exposure are recorded as a known open item,
  not addressed in this ADR.
- F-72 is resolved when the replacement tests are committed and pass
  under both `cargo test` and `cargo +nightly miri test`.
