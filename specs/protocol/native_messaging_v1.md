<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Arcanum Browser Native Messaging Protocol v1

**Status:** Specification — MVP-4
**Fuzz target:** `fuzz/fuzz_targets/native_message.rs`

---

## 1. Security Model

The browser extension is **not** a trusted vault container. It is a requestor
that passes through the Native Messaging Host, local policy engine, and
explicit user approval gates.

The extension never receives full vault export capability.

---

## 2. Message Envelope

```json
{
  "version": 1,
  "request_id": "<128-bit random hex>",
  "extension_id": "<browser-assigned extension ID>",
  "operation": "<see allowed operations>",
  "session_handle": "<opaque session handle>",
  "payload": {},
  "created_at_ms": 0
}
```

---

## 3. Allowed MVP Operations

| Operation | Returns Secret? | Requires Approval? |
|---|:---:|:---:|
| `health_check` | No | No |
| `search_items` | No | No (vault unlocked) |
| `request_secret_view` | One field via lease/handle | Yes |
| `copy_secret` | Clipboard only | Yes |
| `cancel_request` | No | No |

---

## 4. Native Host Rules

- Accept messages only from allowlisted extension IDs configured at install time
- Validate every message against strict JSON schema before dispatch
- Reject: unknown operations, unknown fields in critical locations, oversized payloads,
  stale timestamps (outside skew window), duplicate request_ids, unauthenticated sessions
- A web page must never talk to the native host directly
- The native host still validates `extension_id` and operation policy independently
- Rate-limit `request_secret_view` and `copy_secret` operations
- Return redacted search results by default (item type and label, no secret value)
- All parser and schema code must have fuzz targets

---

## 5. Parser Requirements

The native messaging parser must:
- Reject malformed JSON
- Reject unknown operations with a defined error response
- Reject `payload` fields that exceed operation-specific size limits
- Reject `created_at_ms` outside the accepted skew window (± 30 seconds recommended)
- Reject duplicate `request_id` within the replay window
- Fail closed on any schema validation error — no partial operation execution
