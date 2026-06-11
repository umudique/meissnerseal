# Contract: meissnerseal-sync-server

**Version:** 0.1.0
**API Status:** Unstable  
**Spec authority:** specs/protocol/sync_profile_v1.md  
**ADRs:** ADR-002 (version vectors), ADR-010 (unrecoverable by default)

---

## Public API Surface (HTTP endpoints)

```
POST /v1/devices/register
POST /v1/devices/approve
GET  /v1/sync/state
POST /v1/sync/blobs
GET  /v1/sync/blobs/{blob_id}
POST /v1/sync/commit
POST /v1/transfer/relay
GET  /v1/transfer/relay/{transfer_id}
```

---

## Guarantees

```
[G-01] Server never receives, stores, or processes vault plaintext.
       All blobs are opaque encrypted bytes.

[G-02] Every authenticated endpoint validates device-signed canonical request.
       Revoked, expired, pending, and unknown devices receive 403.

[G-03] Nonces in device-signed requests are stored server-side.
       Replayed nonces within the replay window are rejected with 401.

[G-04] Blob IDs are opaque random identifiers.
       Blob IDs are never derived from item names, item IDs, or secret metadata.

[G-05] Server logs contain only operational metadata:
       timestamps, device IDs, blob counts, revision IDs.
       No secret names, secret values, or decrypted content in logs.

[G-06] Rate limits apply to every endpoint by account, IP, and token class.

[G-07] Transfer relay TTL is enforced server-side.
       Expired envelopes are rejected before storage and deleted by background job.
```

---

## Anti-Guarantees

```
[A-01] Server visibility is documented in specs/protocol/sync_profile_v1.md §8.
       Blob size, timestamps, and device IDs are visible to the operator.

[A-02] Insider admin can observe traffic patterns and metadata.
       This is documented in the threat model (Insider admin adversary).

[A-03] Server does NOT enforce conflict resolution.
       Conflict detection is client-side (version vectors).
       Server stores all revisions; client resolves.
```

---

## Preconditions

```
[P-01] First device registration requires either:
       — first-device bootstrap mode (no prior approved devices), or
       — a signed one-time enrollment capability from an approved device.

[P-02] Device approval requires a device-signed pairing transcript.
       Approval without a valid transcript is rejected.
```

---

## Invariants

```
[I-01] This server never decrypts any blob or envelope content.
[I-02] Support tooling has no path to access vault plaintext.
[I-03] Log rotation must preserve the no-secret-in-logs guarantee.
```
