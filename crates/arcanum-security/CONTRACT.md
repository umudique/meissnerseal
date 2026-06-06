# Contract: arcanum-security

**Version:** 0.1.0
**API Status:** Stable  
**Spec authority:** specs/security/security_assurance.md  
**ADRs:** ADR-004 (handle-and-lease FFI), ADR-014 (noise hierarchy)

---

## Public API Surface

```
secret_lifecycle::
  SecretBytes              — zeroizing byte wrapper
  SecretString             — zeroizing string wrapper (UTF-8)
  with_secret<F, R>(bytes, f: F) -> R   — scoped secret access

redaction::
  redacted_debug!(type)    — macro: implement Debug as [REDACTED]

policy::
  PolicyEngine             — manages session TTL, clipboard timeout, auto-lock
  SessionPolicy { ttl_ms, clipboard_timeout_ms, auto_lock_ms }

hardware::
  HardwareAdapter          — OS secure storage abstraction
  store_device_key(id, key) -> Result<()>
  load_device_key(id) -> Result<SecretBytes>
  capability() -> HardwareCapability  — which features are available

audit_guard::
  AuditEvent               — event type with no secret fields
  emit(event: AuditEvent)  — emits structured event to caller pipeline; no direct I/O
```

---

## Guarantees

```
[G-01] SecretBytes and SecretString zeroize their backing memory on drop.

[G-02] Debug implementation for all secret types outputs [REDACTED].
       No secret value appears in formatted output, logs, or error messages.

[G-03] AuditEvent types enforce at compile time that secret fields cannot
       be set. Audit log never contains secret values.

[G-04] HardwareAdapter gracefully degrades when platform support is
       unavailable. It returns Err with a documented capability enum,
       not a silent fallback that weakens security assumptions.

[G-05] PolicyEngine coordinates session expiry, clipboard timeout, and
       auto-lock from a single authoritative source.
```

---

## Anti-Guarantees

```
[A-01] Does NOT guarantee zeroization against kernel-level memory dumps
       or hardware memory acquisition.

[A-02] Does NOT guarantee swap/hibernation protection. Platform-dependent.
       Documented in threat_model.md Out of Scope.

[A-03] Does NOT guarantee Dart/Flutter GC will release secret references
       on schedule. Dart heap is outside this crate's boundary.

[A-04] HardwareAdapter does NOT guarantee equal security across all platforms.
       TPM, Secure Enclave, TrustZone have different security properties.
```

---

## Preconditions

```
[P-01] Callers must not copy, clone, or derive raw pointers from the
       byte slice provided by with_secret. The type system prevents
       reference escapes but cannot prevent value copies inside the
       closure — this is a caller obligation, not a compile-time guarantee.

[P-02] AuditEvent fields must be populated only with non-secret operational
       metadata (item_id, timestamp, device_id — never item value).
```

---

## Invariants

```
[I-01] This crate never writes to disk, network, or external log systems
       directly. It emits structured events; the caller writes them.
[I-02] All secret wrapper types in this crate are ZeroizeOnDrop.
```
