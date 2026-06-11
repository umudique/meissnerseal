<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-010: Vault Unrecoverable Without Recovery Kit

**Date:** 2025-06
**Status:** Accepted

## Context

Many secrets management products offer server-assisted password reset,
compromising zero-knowledge guarantees. Arcanum must decide its recovery posture.

## Decision

If the user loses the master password and has neither an approved unlocked device
nor a valid recovery kit, the vault is **permanently unrecoverable**.

Arcanum servers must not be able to reset or recover a zero-knowledge vault.

## Rationale

- Server-assisted recovery requires the server to hold key material or a
  reset mechanism, compromising zero-knowledge
- The product stores seed phrases and signing keys that are themselves unrecoverable
  if compromised — the vault recovery model must match this threat level
- Users who understand they are protecting unrecoverable assets will accept
  the responsibility of maintaining a recovery kit
- Clear documentation prevents false expectations

## Consequences

- Recovery kit generation is part of MVP-1 onboarding
- CLI and desktop app must prominently warn during vault creation
- `SECURITY.md` and product documentation must explicitly state the baseline rule
- Shamir Secret Sharing and social/guardian recovery are future optional profiles
  and must not be implied in product messaging until implemented and reviewed
- Recovery kit must be Bech32m-encoded (ADR-003) and user-controlled
