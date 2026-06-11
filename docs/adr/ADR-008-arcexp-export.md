<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-008: Encrypted .arcexp as Default Export Format

**Date:** 2025-06
**Status:** Accepted

## Context

The CLI includes `arcanum export` and `arcanum import`. A format must be defined.
Plaintext JSON/CSV exports are a common security failure mode in secrets management tools.

## Decision

The default export format is an encrypted `.arcexp` bundle protected by a
user-supplied export passphrase, derived via KDF_ARGON2ID_V1.

Plaintext JSON/CSV import is allowed only as an explicitly unsafe development
and testing path, behind a mandatory unsafe flag and warning.

## Rationale

- Encrypted-by-default prevents accidental plaintext backup leakage
- `.arcexp` extension is clearly Arcanum-specific; not confused with vault files (`.arcv`)
- Consistent with the "no plaintext to disk" principle
- Developers legitimately need to import test fixtures — allowed with explicit warning

## Consequences

- `arcanum export` always produces `.arcexp` by default; passphrase required
- `arcanum import --unsafe-plaintext` flag required for JSON/CSV; emits loud warning
- `.arcexp` format uses same AEAD/KDF as vault format; reuses the same TLV structure
- Export fuzz target added to `fuzz/fuzz_targets/`
