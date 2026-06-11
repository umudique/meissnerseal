<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-006: KDF_ARGON2ID_V1 Parameter Set

**Date:** 2025-06
**Status:** Accepted

## Context

The Argon2id KDF requires concrete parameter values for MVP-0.
Parameters must be stored in the vault header, not hardcoded, to allow future upgrades.

## Decision

```
m_cost_kib   = 65536  (64 MiB)
t_cost       = 3
p_lanes      = 4
output_len   = 32 bytes
argon2_version = 0x13 (current)
```

Salt: `"meissnerseal-argon2id-salt-v1" || vault_id`

## Rationale

- 64 MiB memory cost aligns with OWASP recommendation for interactive login (2023)
- t=3 iterations provide conservative protection without excessive latency
- p=4 uses available parallelism on developer machines without making the format
  platform-dependent (p is an implementation hint, not a security guarantee alone)
- 32-byte output gives 256-bit Master Unlock Key material
- Domain-separated salt (vault-specific) prevents cross-vault key reuse

## Consequences

- All parameters stored in vault header TLV (tags 0x0101–0x0105)
- Implementations read parameters from header on unlock; never hardcode them
- Future parameter upgrades write new values into a new vault generation
- Test vectors must deterministically reproduce the derived key
- Unlock code must validate parameters against safe implementation limits
