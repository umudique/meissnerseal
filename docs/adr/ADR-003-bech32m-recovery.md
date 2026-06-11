<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-003: Bech32m Encoding for Recovery Secrets

**Date:** 2025-06
**Status:** Accepted

## Context

The recovery secret must be human-transcribable (printable, writable by hand).
An encoding scheme must be chosen.

## Alternatives Considered

1. **BIP-39 mnemonic (24 words):** well-known in crypto, but implies wallet seed phrase
   compatibility, increasing user confusion and potential misuse.
2. **Hex string:** high entropy, poor human readability, prone to transcription errors.
3. **Base64:** compact but includes confusable characters (+, /, =, 0/O, 1/l).
4. **Bech32m:** case-insensitive, no confusable characters, BCH checksum, used in Bitcoin
   SegWit addresses; good transcription error detection.

## Decision

Bech32m encoding with HRP `arc`, carrying: profile_id || recovery_id || 256-bit seed.

Format: `arc1<base32-data><6-char-checksum>`

## Rationale

- Checksum catches single-character transcription errors
- No confusable characters (0/O, 1/l/I excluded)
- Case-insensitive input
- Does not imply BIP-39 / wallet seed compatibility
- 256-bit entropy from OS CSPRNG

## Consequences

- Recovery secrets look like `arc1...` and are clearly Arcanum-specific
- Bech32m library required (available in Rust: `bech32` crate)
- Test vectors must cover: valid decode, checksum error, wrong HRP, wrong profile_id
- Optional passphrase hardening via Argon2id is a separate optional profile
