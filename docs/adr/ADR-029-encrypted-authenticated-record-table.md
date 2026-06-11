<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-029: Encrypted, Authenticated Record Table

**Status:** Accepted
**Date:** 2026-06-09
**Related:** F-14, F-13 (finding_register), vault_format_v1.md §5–§7,
             crypto_design.md §5 (Metadata Encryption Key), CONTRACT.md I-03

---

## Context

The vault record table (vault_format_v1.md §5) is stored **cleartext and
unauthenticated**. This produces two deficiencies:

1. **Integrity gap (F-14, CWE-345).** A tampered table — offsets, record_ids,
   revision_ids — is only caught insofar as a record frame's AEAD AAD happens to
   bind the affected field. Once a consumer (item enumeration, future sync
   reconciliation) trusts table metadata, this is an exploitable gap.
2. **Metadata leakage.** Anyone with the file reads record count, record kinds and
   revision counts without unlocking — contradicting I-03 (cleartext metadata
   limited to what unlock/migration require) and the threat model's
   metadata-leakage concern for the local file.

Item operations (CORE-9) make the table the **first real consumer**, so this must
be resolved before MVP-0 item operations ship (decision "Çatal-1 = A", 2026-06-09).

The key hierarchy already derives a **Metadata Encryption Key (MEK)**
(crypto_design.md §5) whose stated purpose is exactly authenticating/encrypting
non-item metadata such as the record table.

---

## Decision

**Encrypt and authenticate the item record table under the MEK with a single AEAD
operation, and bootstrap unlock without any cleartext table or locator.**

1. **One primitive, both properties.** The item record table is sealed with AEAD
   (XChaCha20-Poly1305, key = MEK, AAD = `vault_id ‖ schema_profile`, plus a fresh
   192-bit random nonce per seal). This yields integrity **and** metadata
   confidentiality together — consistent with crypto_design.md §9 "no
   unauthenticated encryption anywhere."

   > **Correction (2026-06-09).** An earlier draft of this ADR put a
   > `table_version_counter` in the AAD. That is removed. (a) It was *circular*:
   > AEAD AAD must be known before decryption, but the counter was specified
   > nowhere cleartext, so the table could not be opened (caught at spec time). (b)
   > It bought no security: the fresh per-seal nonce already separates versions
   > cryptographically, and a counter in the AAD does **not** prevent table
   > rollback — an attacker swapping in an older sealed table simply recomputes the
   > AAD from that table's own (cleartext) counter, which verifies. Real anti-
   > rollback requires the expected version anchored in an AEAD-authenticated field
   > the attacker cannot independently swap (e.g. bound into the WrappedRootKey
   > frame AAD). **Table freshness / anti-rollback is therefore deferred to the
   > sync/transfer era**, where it is designed together with version vectors
   > (ADR-002) and the table-trust requirement (F-14). MVP-0 (single-writer, local,
   > alpha) does not include local-file rollback in its threat model.
2. **Fixed-position Wrapped Root Key — no cleartext locator.** The WrappedRootKey
   record frame is placed at a **fixed, format-defined position** (immediately
   after the header), so unlock can find it without any cleartext table or
   pointer. The only cleartext that remains is the **header** (KDF params,
   vault_id, header_nonce) — unavoidable because it is required to run Argon2id at
   all, and it discloses nothing beyond what the magic bytes already announce
   ("this is an MeissnerSeal vault, format vN").
3. **Bootstrap order.** header (cleartext) → WrappedRootKey frame (fixed position,
   ciphertext) → MEK-sealed record table → item record frames. Unlock: header →
   derive VKEK from password → decrypt WRK → VRK → derive MEK → decrypt the table →
   seek item frames.
4. **Residual + mitigation.** The sealed table's *length* stays in cleartext (to
   delimit it), leaking an approximate record count. This MAY be blurred by
   padding the sealed table to bucketed sizes (the "future padding" affordance the
   transfer spec already anticipates).
5. **schema_profile bump.** This is a format change; it is introduced under a new
   `schema_profile` value. On mutation the whole table is re-sealed under MEK
   (cheap — the table is small and **no item plaintext is touched**, consistent
   with the whole-vault rewrite of CORE-8).

This **resolves F-14**: the table is authenticated, so the two-revision-source
ambiguity with F-13 collapses (a consumer may trust the MEK-verified table); it is
now confidential as well.

---

## Alternatives Considered

**Bare MAC over the cleartext table.** Rejected: provides integrity but not
confidentiality, and using the MEK (an *encryption* key) as a bare MAC key is
off-purpose key-reuse; a separate MAC key would be needed, for strictly less
benefit than AEAD.

**Cleartext bootstrap pointer to the WRK frame.** Rejected: a fixed WRK position
removes the need for any locator, shrinking cleartext to the unavoidable header.

**Leave F-14 deferred (frame-authoritative, table advisory).** Rejected: item
enumeration consumes the table now; advisory-only is no longer tenable in MVP-0.

---

## Consequences

- vault_format_v1.md §5–§7 are revised: encrypted+authenticated table (AAD =
  `vault_id ‖ schema_profile`, fresh per-seal nonce — no version counter, see
  Correction), fixed WRK position, optional bucketed padding, new `schema_profile`.
  This revision must land **before CORE-8** (multi-record persist) so the format is
  built once.
- CORE-9 item enumeration decrypts the table under MEK post-unlock.
- F-14 moves to resolved upon implementation; F-13's table revision_id becomes a
  MEK-authenticated value.
- The test vectors for the vault format are regenerated (TV-4 drift guard) for the
  new schema_profile.
