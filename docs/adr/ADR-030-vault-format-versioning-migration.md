# ADR-030: Vault Format Versioning and Migration Policy (schema_profile)

**Status:** Accepted
**Date:** 2026-06-09
**Related:** ADR-029 (encrypted record table), vault_format_v1.md §3/§8/§10,
             overview.md §6 (Migration Manager)

---

## Context

`schema_profile` (header tag `0x0006`, u16le enum, **critical**, bound into the
canonical AAD) is the on-disk record-layout version knob. The vault format spec
designs it as the field to increment when the record layout changes, but its
**evolution and migration semantics were left implicit.**

ADR-029 introduces the **first** increment of this field (cleartext table →
MEK-encrypted, authenticated table). The moment of the first version change is
when the versioning model must be made explicit — a fail-closed security project
cannot leave "what happens when a reader meets an unknown profile, and how a vault
moves between profiles" undefined.

---

## Decision

1. **Fail-closed forward-incompatibility.** A reader accepts only the
   `schema_profile` values it implements. An unknown or newer value is **rejected**
   — never best-effort or partially parsed. This is enforced structurally:
   `schema_profile` is a *critical* TLV (unknown critical tag → reject, §10) and is
   AAD-bound (so it cannot be silently downgraded).

2. **No silent in-place upgrade.** A format change is a *new* `schema_profile`
   value, never an ambiguous reinterpretation of an existing one. A vault is never
   partially rewritten across versions as a side effect of opening it.

3. **Migration is explicit, whole-vault, and crash-safe.** When migration is
   offered, the Migration Manager reads a *fully known* old profile and
   re-serializes the entire vault under the new profile through the §8 crash-safe
   path (unique temp → fsync → atomic rename → fsync parent). Migration is
   one-directional and validated by cross-version test vectors. There is no
   in-place, partial, or best-effort upgrade.

4. **Every profile ships with authoritative vectors.** A new `schema_profile`
   value is added only together with its own test vectors (cross-verified, under
   the TV-4 drift guard). No profile without vectors.

5. **MVP-0 application.** `SCHEMA_ARCANUM_RECORDS_V1 = 0x0001` (the cleartext-table
   layout from the CORE-3..7 development work) is a **pre-release internal
   development format and is NOT shipped to any user.** ADR-029's encrypted,
   authenticated-table layout ships as the MVP-0 format under a new value
   `SCHEMA_ARCANUM_RECORDS_V2 = 0x0002`; readers reject `V1`. **No V1→V2 migration
   path is shipped** — no user ever holds a V1 vault, so carrying one would be pure
   debt. The first real migration path is defined when the first *post-release*
   increment occurs.

---

## Alternatives Considered

**Best-effort forward compatibility (parse what you can of a newer profile).**
Rejected: invites silent misparse and downgrade; violates fail-closed.

**Auto-migrate on open.** Rejected: hidden writes, a crash window on every open,
and surprising the user; migration must be an explicit, tested action.

**Carry a V1→V2 migration path in MVP-0.** Rejected: V1 never shipped; the path
would protect no real vault and add untested code on a security-critical path.

---

## Consequences

- vault_format_v1.md §3 (enum assignments) adds `SCHEMA_ARCANUM_RECORDS_V2`; §10
  states the unknown-profile reject rule explicitly; the Migration Manager
  contract (overview.md §6) is defined as whole-vault, crash-safe, one-directional.
- ADR-029's spec revision assigns `schema_profile = V2` for the encrypted table
  and marks `V1` as unshipped/rejected.
- Future profile increments (e.g. a post-quantum-at-rest profile, AES-GCM-strict
  layout, padding changes) follow this policy by default; deviations need their own
  ADR.
