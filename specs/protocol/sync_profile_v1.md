<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# MeissnerSeal Sync Profile v1

**Status:** Specification — MVP-3
**Formal model:** `specs/formal/sync_state_machine.tla` (TLA+ — MVP-3)
**Fuzz target:** `fuzz/fuzz_targets/sync_envelope.rs`
**Test vectors:** `test-vectors/sync_envelope_v1.json`

---

## 1. Zero-Knowledge Principle

The sync server stores only encrypted blobs. It never receives:
- Vault plaintext
- Master passwords
- Item keys or unwrapped vault root keys
- Secret names or item metadata in cleartext

---

## 2. Sync Conflict Model — Version Vectors

**Decision:** Client-side version vectors for concurrency detection.
The server maintains a monotonic commit index for ordering and pagination only —
it is not the source of truth for conflict semantics.

### Version Vector

```
VersionVector = Map<DeviceId, Counter>
```

A new local edit increments the local device counter.
When two revisions are concurrent (neither vector dominates), MeissnerSeal marks a conflict.

### Conflict Resolution Rules

- **Last-write-wins is forbidden** for critical secret payloads
- Conflicting versions are preserved as separate encrypted revisions
- The UI presents both versions; user chooses, merges manually, or keeps both
- **Items that must not be auto-merged:** SeedPhrase, SigningKey, SshPrivateKey, ApiToken, RecoveryCode
- Metadata-only conflicts may use guided merge (future); MVP preserves both versions
- Deletes are tombstones; delete-vs-update requires explicit user confirmation

---

## 3. Revision Model

- Every edit creates an **immutable encrypted revision blob**
- Blob IDs: random or content-addressed opaque identifiers — must not reveal item names or types
- In-place overwrites are avoided; tombstones represent deletes
- Server stores: encrypted blobs, device IDs/public keys, revision metadata, operational timestamps

---

## 4. Local Change Journal

- Journal entries kept until acknowledged by server and reconciled by client
- Default retention after acknowledgement: **30 days minimum**, configurable
- Tombstones retained long enough for offline devices to learn deletes
- Journal cleanup must not remove unresolved conflict evidence

---

## 5. Version Vector Pruning and Compaction

### Policy

- Active approved devices remain in version vectors permanently
- Revoked devices remain until **all currently approved devices** have observed
  the signed revocation event and advanced past the revoked device's last counter
- A compaction checkpoint may remove a revoked device only if it records:
  - revoked `device_id`
  - last retained counter value
  - checkpoint version vector
  - signing device_id
  - timestamp
  - signature over the compaction event
- Default minimum retention for revoked-device entries: **90 days**
- Never less than the configured offline-device support window
- MVP soft limit: **16 approved devices** per individual vault before requiring cleanup
- Pruning is itself a sync event and must be modeled in TLA+

---

## 6. Sync API Authentication v1

Each approved device has a mandatory signing key. The server authenticates
devices, not vault plaintext or master passwords.

### Request Authentication Header

```http
Authorization: MeissnerSeal-Device-V1 device_id="...", key_id="...", nonce="...", ts="...", sig="..."
X-MeissnerSeal-Body-SHA256: <hex-encoded-sha256-body-digest>
```

### Canonical Request String (signed)

```
ARCANUM-SYNC-REQUEST-V1\n
\n
{method}\n
\n
{path}\n
\n
{query_canonical}\n
\n
{body_sha256}\n
\n
{device_id}\n
\n
{account_or_vault_sync_id}\n
\n
{timestamp_ms}\n
\n
{nonce}\n
```

### Authentication Rules

- `POST /v1/devices/register`: allowed only for first-device bootstrap or with a signed one-time device-enrollment capability from an already approved device
- `POST /v1/devices/approve`: must be signed by an already approved device and must reference the signed pairing transcript
- All other endpoints require device-signed authentication
- Nonces must be unique per device within the replay window; stored server-side
- Timestamps outside the accepted skew window are rejected
- Revoked, expired, pending, or unknown devices cannot commit sync state
- Optional mTLS or account-session cookies may be added as transport hardening; they do not replace device signatures

---

## 7. Sync API Endpoints

```http
POST /v1/devices/register
POST /v1/devices/approve
GET  /v1/sync/state
POST /v1/sync/blobs
GET  /v1/sync/blobs/{blob_id}
POST /v1/sync/commit
POST /v1/transfer/relay
GET  /v1/transfer/relay/{transfer_id}
```

All sync payloads containing vault data must be encrypted client-side.

---

## 8. Server Data Visibility

| Data | Server Visibility |
|---|---|
| User account email | Visible in managed sync |
| Device ID | Visible |
| Device public keys | Visible |
| Encrypted blobs | Visible but opaque |
| Blob size | Visible |
| Sync timestamps | Visible |
| IP address | Operationally visible |
| Secret names | Must not be visible |
| Secret values | Never visible |
| Vault root key | Never visible |

---

## 9. TLA+ Model Scope

`specs/formal/sync_state_machine.tla` must model:
- Offline edits from two devices
- Concurrent update/update conflict
- Delete/update conflict
- Tombstone propagation
- Idempotent replay of already-seen revisions
- Server reordering that does not lose client revisions
- Compaction checkpoint correctness
