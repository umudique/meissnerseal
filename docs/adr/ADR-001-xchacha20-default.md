<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-001: XChaCha20-Poly1305 as Default AEAD

**Date:** 2025-06
**Status:** Accepted

## Context

A default AEAD algorithm must be chosen for vault records, sync envelopes, and export bundles.
AES-256-GCM and XChaCha20-Poly1305 are both well-reviewed options.

## Decision

XChaCha20-Poly1305 (`AEAD_XCHACHA20_POLY1305_V1`) is the default AEAD profile.
AES-256-GCM (`AEAD_AES_256_GCM_STRICT_V1`) is a strict optional profile.

## Rationale

- 192-bit random nonces make nonce collision probability negligible across concurrent sync edits
- Nonce misuse resistance is significantly better than AES-GCM's 96-bit nonces
- Software performance is competitive; no requirement for AES hardware acceleration
- AES-GCM with 96-bit nonces under high write volume or concurrent sync is risky
- AES-GCM remains available for environments where AES hardware acceleration is required,
  but only under the stricter fresh-record-key-per-revision requirement

## Consequences

- Vault files, sync envelopes, and export bundles use XChaCha20-Poly1305 by default
- AES-GCM implementations must reject caller-supplied nonces outside test modules
- AES-GCM implementations must enforce fresh random Record Encryption Key per revision
- Both profiles have test vectors and are crypto-agile via the vault header AEAD profile field
