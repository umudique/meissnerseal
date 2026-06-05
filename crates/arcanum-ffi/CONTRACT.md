# Contract: arcanum-ffi

**Version:** 0.1.0  
**Spec authority:** specs/crypto/crypto_design.md §3 (FFI section)  
**ADRs:** ADR-004 (handle-and-lease FFI)

---

## Public API Surface

```
VaultSessionHandle(u64)     — opaque session reference for Dart
SecretViewHandle(u64)       — opaque secret lease reference for Dart

create_vault(params) -> Result<VaultSessionHandle>
unlock_vault(path, master_secret) -> Result<VaultSessionHandle>
lock_vault(handle: VaultSessionHandle) -> Result<()>

list_items(session: VaultSessionHandle) -> Result<Vec<ItemSummary>>
// ItemSummary contains: item_id, item_type, label — no secret values

create_secret_view(
  session: VaultSessionHandle,
  item_id: ItemId,
  field: SecretField,
  ttl_ms: u32,
) -> Result<SecretViewHandle>

read_secret_view(handle: SecretViewHandle) -> Result<SecretFieldValue>
// SecretFieldValue: short-lived, must be consumed immediately by caller

release_secret_view(handle: SecretViewHandle) -> Result<()>
// Zeroes the backing memory and invalidates the handle
```

---

## Guarantees

```
[G-01] Dart never holds a raw plaintext buffer. All secrets are accessed
       through SecretViewHandle with a mandatory TTL.

[G-02] SecretViewHandle expires after ttl_ms milliseconds.
       Expired handles return Err on any subsequent read.

[G-03] release_secret_view zeroes the backing memory before invalidating
       the handle.

[G-04] list_items never returns secret field values. Only item_id,
       item_type, and label (which must be non-sensitive).

[G-05] Every unsafe FFI function has a // SAFETY: comment.
```

---

## Anti-Guarantees

```
[A-01] Does NOT prevent Dart GC from holding references after release.
       Dart heap is not within the trusted memory boundary.

[A-02] Does NOT guarantee that the Dart runtime zeroes memory on GC.

[A-03] Does NOT protect against OS-level memory acquisition after
       Dart has held the value.
```

---

## Dart Boundary Limitations (must be documented in product)

The following limitations must be documented for developers using the FFI:
- Dart GC timing is non-deterministic
- Dart widget state, provider state, and route arguments must not hold
  plaintext secrets
- Production builds must disable Flutter debug overlays and hot-reload
- OS swap, screenshots, and crash dumps can capture Dart heap contents

---

## Preconditions

```
[P-01] Caller must call release_secret_view after consuming the value.
       Failing to release causes the backing memory to remain until TTL expiry.

[P-02] VaultSessionHandle must not be shared across threads without
       explicit synchronization.
```
