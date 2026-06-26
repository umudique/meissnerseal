<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-039: Crypto-Agility as an Architectural Requirement

**Status:** Accepted  
**Date:** 2026-06-26  
**Related:** ADR-034 (RustCrypto ML-KEM backend),
             ADR-035 (UG combiner hybrid KEM),
             ADR-036 (ML-KEM-768 parameter set),
             specs/protocol/vault_format_v1.md §3 (profile IDs),
             specs/security/threat_model.md

---

## Context

MeissnerSeal stores secrets that are difficult or impossible to rotate:
seed phrases, SSH keys, long-lived API tokens. AGENTS.md §1 states this
explicitly. This creates an asymmetric exposure window: a vault encrypted
today may be captured and held by an adversary, then decrypted years
later when cryptanalytic capabilities improve.

This threat — commonly called "Harvest Now, Decrypt Later" (HNDL) — is
the primary long-horizon risk for a secrets vault. Nation-state actors
with network access and storage capacity can harvest ciphertext today
and wait. The time horizon for cryptographically-relevant quantum
computers is uncertain but widely cited as 10–20 years.

MeissnerSeal already takes two correct steps:

1. The transfer protocol uses a hybrid KEM
   (X25519 + ML-KEM-768, ADR-035) so a classical break of X25519 alone
   does not compromise transfer confidentiality.

2. The vault format uses profile IDs (vault_format_v1.md §3) and a
   versioned KDF TLV, creating structural hooks for algorithm migration.

What is not recorded: the architectural commitment that these hooks
exist for a reason, the criteria that would trigger their use, and the
fact that migration procedure is deliberately deferred.

Without this record, future contributors may not understand why the
profile ID system exists, may remove it as apparent over-engineering,
or may not know that a FIPS 203 revision should trigger a migration
planning exercise.

---

## Decision

### 1. Crypto-agility is an explicit architectural requirement

MeissnerSeal must be designed so that a change in the selected
cryptographic algorithm — KEM, AEAD, or KDF — can be executed without
discarding existing vault data. "Agility" here means:

- Existing vaults can be re-encrypted under a new algorithm through a
  defined migration procedure.
- The migration procedure is user-initiated and auditable, not silent.
- Old and new algorithm versions coexist during a migration window.

This requirement applies to all three cryptographic layers:
- **KEM** (transfer protocol): hybrid construction, governed by ADR-035
- **AEAD** (vault encryption): XChaCha20-Poly1305 with profile ID
- **KDF** (key derivation): Argon2id with versioned TLV, governed by
  vault_format_v1.md §4

### 2. The profile ID and versioning systems are load-bearing

The profile ID fields in vault_format_v1.md §3 and the KDF parameter
TLV in §4 are not optional extensibility points — they are the
mechanism by which algorithm migration is made possible. They must not
be removed or collapsed to a single hardcoded value. Any ADR that
proposes simplifying the format must explicitly address how algorithm
migration would work without them.

### 3. Migration procedure is deferred

The concrete migration procedure — how a user re-encrypts an existing
vault under a new algorithm, what the new vault format version looks
like, what the transition states are — is not defined in this ADR.

This is a deliberate deferral. The correct migration procedure depends
on which algorithm is being replaced and why. Specifying it now against
a hypothetical future algorithm change would produce a procedure that
does not match the actual change when it occurs.

The migration procedure will be defined in `specs/protocol/` when one
of the following triggers is met:

**Trigger A — Standard revision:**
NIST issues a revision to FIPS 203 (ML-KEM) that deprecates ML-KEM-768
or introduces a new mandatory parameter set.

**Trigger B — Cryptanalytic break:**
A practical attack against ML-KEM-768, Argon2id, or
XChaCha20-Poly1305 is published or credibly reported.

**Trigger C — Proactive rotation window:**
The project reaches a milestone at which vault data has been encrypted
for more than five years and no migration has occurred. At that point,
a proactive migration planning exercise is warranted regardless of
standard status.

### 4. Vault encryption HNDL exposure assessment

The lokal vault encryption layer (XChaCha20-Poly1305, Argon2id KDF)
is symmetric. Grover's algorithm halves the effective key strength:
a 256-bit key becomes 128-bit equivalent under a quantum adversary.
128-bit symmetric security is currently considered sufficient. This
does not eliminate HNDL risk but characterises it as lower urgency
than the transfer layer.

The transfer layer hybrid KEM (ADR-035) addresses HNDL for data in
transit: breaking X25519 classically does not compromise
confidentiality while ML-KEM-768 remains unbroken.

---

## Alternatives Considered

**Fix the algorithm now and remove agility.** Would simplify the
format but eliminates the ability to respond to future breaks. Not
acceptable for a vault that holds non-rotatable secrets.

**Define the migration procedure now.** Premature. The procedure
depends on the specific algorithm being replaced and the operational
context. A generic procedure written now against a hypothetical change
will likely be wrong in the details that matter.

**Add a second PQC AEAD layer to vault encryption today.** Would
reduce HNDL exposure for stored data. The cost is format complexity
and a dependency on a PQC AEAD that is not yet standardised (NIST
has not selected a PQC-based authenticated encryption scheme as of
this writing). Revisit under Trigger A or B.

---

## Consequences

- Profile ID fields and KDF TLV versioning in vault_format_v1.md are
  explicitly protected from simplification without an ADR.
- Migration procedure is a known open item, tracked here rather than
  silently absent.
- Trigger A/B/C create concrete conditions for reopening this ADR.
- No implementation changes required now.
