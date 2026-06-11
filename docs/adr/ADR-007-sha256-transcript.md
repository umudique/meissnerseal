<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-007: SHA-256 Transcript Hash for MVP Transfer Profile

**Date:** 2025-06
**Status:** Accepted

## Context

The hybrid transfer protocol uses a transcript hash to bind all protocol parameters.
A hash algorithm must be chosen consistently with the HKDF algorithm.

## Decision

MVP transfer profile `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1`:
- Transcript hash: SHA-256 (32 bytes)
- HKDF: HKDF-SHA256 for Extract and Expand

SHA-384 is reserved for a future profile.

## Rationale

- SHA-256 + HKDF-SHA256 are internally consistent
- The TransferEnvelope struct has `transcript_hash: [u8; 32]` — 32 bytes = SHA-256
- Mixing SHA-256 transcript hash with HKDF-SHA384 creates a type mismatch
- SHA-256 provides 128-bit collision resistance, sufficient for the transcript binding purpose
- A future ML-KEM-1024 profile can define `TRANSFER_HYBRID_X25519_MLKEM1024_SHA384_V2`
  with 48-byte transcript hash, HKDF-SHA384, and new envelope encoding

## Consequences

- Implementations that attempt to use HKDF-SHA384 with the v1 profile must be rejected
- Test vectors explicitly test that SHA-384 inputs are rejected at profile validation
- Profile ID `TransferProfileId` must be in the transcript and envelope; mismatch → reject
