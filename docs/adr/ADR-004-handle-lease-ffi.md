<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-004: Handle-and-Lease Model for FFI/Dart Plaintext

**Date:** 2025-06
**Status:** Accepted

## Context

Rust zeroization does not protect plaintext once it is copied into the Dart/Flutter heap.
Dart GC timing is non-deterministic. Long-lived plaintext in Flutter widget state
creates a memory hygiene risk.

## Decision

The default FFI model is handle-based and scoped.
Dart stores opaque handles and display leases, not reusable plaintext strings.

```rust
pub struct VaultSessionHandle(u64);
pub struct SecretViewHandle(u64);
```

Secret access through `create_secret_view(session, item_id, field, ttl_ms)`.
View expires after TTL (default 30 seconds). Released explicitly with `release_secret_view`.

## Rationale

- Minimizes time that plaintext exists in the Dart heap
- Prevents plaintext from being stored in route arguments, provider state, or logs
- Rust side can zeroize backing memory on release
- Flutter GC still controls when Dart objects are collected — documented limitation

## Consequences

- App state stores item IDs, labels, redacted previews, and SecretViewHandle only
- Reveal flows use short-lived modal with ≤30s TTL
- Clipboard operations routed through Rust/platform clipboard manager where practical
- Production builds disable debug overlays and hot-reload state snapshots
- Documentation must explicitly state: Dart GC timing, OS swap, screenshots,
  accessibility APIs, and crash dump capture cannot be fully controlled by MeissnerSeal
- This is a mitigation strategy, not a perfect memory-safety guarantee
