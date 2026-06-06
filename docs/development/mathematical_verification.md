# Mathematical Verification Guide

**Decision:** ADR-015  
**Audience:** All implementation agents and contributors

---

## Proof Scope

Formal verification in Arcanum covers specific, bounded properties of the
cryptographic core. Knowing what is and is not proven is as important as
knowing that proofs exist.

**Primitive correctness** (`arcanum-crypto`) — Kani bounded proofs:
- `Key<N>` types — length invariants at compile time (const generics)
- `build_aad_v1` / `AAD_V1` construction — output length == 74 invariant
- `argon2id_v1_salt`, `derive_master_unlock_key`, `derive_vkek` — output length contracts
- `hkdf_info_string` — valid ASCII output
- Nonce generation — output length matches AEAD profile

**Protocol correctness** (`arcanum-core`) — Kani bounds + formal models:
- TLV parser — no buffer overread (Kani)
- Record frame parser — `frame_len` bounds respected (Kani)
- Transfer replay / downgrade rejection — ProVerif symbolic model (MVP-2)
- Sync conflict detection / tombstone propagation — TLA+ state machine (MVP-3)

**Proof does not cover:**
- Correctness of underlying cryptographic primitives (AES-GCM, ML-KEM, Argon2id) — these are verified upstream by RustCrypto
- Operating system memory safety or entropy quality
- UI layer memory handling (Flutter heap is outside the trusted boundary)
- Network transport or sync protocol security
- Side-channel resistance beyond what `subtle` crate provides at the library level
- The whole product being "secure" — proof establishes local invariants, not end-to-end guarantees

This scope follows the same discipline as Apple corecrypto's formal verification:
claims are bounded, falsifiable, and tied to specific functions and properties.

---

## Why Mathematical Verification

Arcanum stores secrets that cannot be rotated. A single incorrect length,
a wrong nonce, or an off-by-one in a parser can be catastrophic.
Tests check examples. Mathematical verification checks all possible inputs.

The four levels in this guide are not alternatives — they are layers.
Each layer catches a different class of error with different effort.

---

## Level 1: Const Generics — Type-Level Length Proofs

### What it does

Encodes the length of cryptographic values into the Rust type system.
The compiler verifies length constraints at compile time.
Zero runtime cost. Zero tooling required beyond `rustc`.

### How to use

All fixed-length cryptographic values must use `Key<N>` from `arcanum-crypto::types`.

```rust
use arcanum_crypto::{AeadKey, XChaCha20Nonce, VaultId};

// The compiler verifies: key is 32 bytes, nonce is 24 bytes.
// Passing a 16-byte key where 32 is required is a compile error.
fn encrypt(key: &AeadKey, nonce: &XChaCha20Nonce) { ... }

// This is a compile error — you cannot confuse key and nonce:
let key = AeadKey::from_bytes([0u8; 32]);
let nonce: XChaCha20Nonce = key;  // ERROR: Key<32> != Key<24>
```

### Available types

```rust
AeadKey         = Key<32>   // XChaCha20-Poly1305 or AES-256-GCM key
XChaCha20Nonce  = Key<24>   // 192-bit nonce
AesGcmNonce     = Key<12>   // 96-bit nonce (strict optional profile)
VaultId         = Key<16>   // vault UUID
RecordId        = Key<16>   // record identifier
RevisionId      = Key<16>   // revision identifier
HeaderNonce     = Key<24>   // vault header nonce
MasterUnlockKey = Key<32>   // Argon2id output
VaultKeyEncKey  = Key<32>   // HKDF-derived from MUK
VaultRootKey    = Key<32>   // vault root key
HkdfPrk         = Key<32>  // HKDF-Extract output
DerivedSubkey   = Key<32>   // HKDF-Expand output
RecordEncKey    = Key<32>   // fresh per-revision encryption key
TransferPayloadKey = Key<32> // hybrid KEM transfer key
```

### Rule for agents

Every function parameter that accepts a fixed-length cryptographic value
must use `Key<N>` or a type alias. Never use `&[u8]` or `Vec<u8>` for
values with a mandatory fixed length.

---

## Level 2: Kani — Bounded Model Checking

### What it does

Kani converts Rust code to SMT formulas and proves properties against
a Z3 solver. Unlike tests (which check examples), Kani checks *all
possible inputs* within a bounded scope.

Example: `kani::any::<[u8; 16]>()` represents every possible 16-byte array.
If the assertion holds for `kani::any()`, it holds for all inputs.

### Installation

```bash
cargo install kani-verifier --locked
cargo kani setup
```

### Running harnesses

```bash
# Run all Kani harnesses in arcanum-crypto
cargo kani --package arcanum-crypto

# Run a specific harness
cargo kani --package arcanum-crypto --harness verify_aad_length
```

### Writing a Kani harness

Harnesses are gated with `#[cfg(kani)]` — they are never compiled into
the production binary.

```rust
// In the same module as the function being proved:

#[cfg(kani)]
#[kani::proof]
fn verify_aad_v1_length() {
    // Non-deterministic inputs — represents ALL possible inputs
    let vault_id: [u8; 16]    = kani::any();
    let record_id: [u8; 16]   = kani::any();
    let revision_id: [u8; 16] = kani::any();

    // Call the function under verification
    let aad = build_aad_v1(vault_id, 1, 1, 1, 1, 0, record_id, revision_id, 1);

    // Property to prove — holds for ALL inputs, not just this example
    kani::assert(aad.len() == 74, "AAD v1 must always be 74 bytes");
}
```

### Kani targets for Arcanum

Each harness traces back to a spec document. The spec is the authoritative
source; the harness is the machine-checked enforcement of that spec's invariants.

| Function | Property | Phase | Spec |
|---|---|---|---|
| `Key<N>::from_bytes` | output length equals N | MVP-0 ✓ | `specs/crypto/crypto_design.md §1` |
| `build_aad_v1` | output length == 74 | MVP-0 | `specs/protocol/vault_format_v1.md` |
| `argon2id_v1_salt` | output length == 40 | MVP-0 | `specs/crypto/crypto_design.md §2` |
| `derive_master_unlock_key` | output length == output_len param | MVP-0 | `specs/crypto/crypto_design.md §3` |
| `derive_vkek` | output length == 32 | MVP-0 | `specs/crypto/crypto_design.md §3` |
| TLV parser | no buffer overread | MVP-0 | `specs/protocol/vault_format_v1.md` |
| Record frame parser | `frame_len` bounds respected | MVP-0 | `specs/protocol/vault_format_v1.md` |
| `hkdf_info_string` | output is valid ASCII | MVP-0 | `specs/crypto/crypto_design.md §3` |
| Nonce generation | output length == AEAD profile nonce length | MVP-0 | `specs/crypto/crypto_design.md §4` |

### Kani harness rules (for agents)

- Harnesses are in the same file as the function under proof
- Every security-critical function in arcanum-crypto must have at least one harness
- Harnesses must use `kani::any()` for inputs — no hardcoded values
- Each `kani::assert` must have a descriptive message
- TODO markers from types.rs are mandatory work items for MVP-0

---

## Level 3: Prusti — Deductive Verification (Beta)

### What it does

Prusti verifies Hoare triples: `{precondition} code {postcondition}`.
Unlike Kani (which checks bounded inputs), Prusti proves properties
for all inputs via deductive reasoning over the program's logic.

### Installation (Beta phase)

```bash
# Prusti requires a specific nightly version
# See https://viperproject.github.io/prusti-dev/user-guide/install.html
# for the currently supported nightly version

cargo install prusti-contracts --locked
```

### Writing Prusti annotations

```rust
use prusti_contracts::*;

#[requires(key.len() == 32)]
#[requires(nonce.len() == 24)]
#[ensures(result.len() == plaintext.len() + 16)]
pub fn xchacha20_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    // Prusti verifies that for ANY key (32 bytes), nonce (24 bytes),
    // and plaintext (any length), the output is always plaintext.len() + 16.
}
```

Prusti annotations are gated with `#[cfg(prusti)]`:

```rust
#[cfg_attr(prusti, requires(key.len() == 32))]
#[cfg_attr(prusti, ensures(result.len() == 32))]
pub fn derive_vkek(key: &[u8], vault_id: &[u8; 16]) -> Vec<u8> {
    // ...
}
```

### Running Prusti

```bash
# Requires the prusti binary to be in PATH
prusti-rustc --edition=2021 src/lib.rs
# or via cargo:
cargo prusti
```

### Prusti targets for Arcanum

| Function | Precondition | Postcondition | Phase |
|---|---|---|---|
| `derive_master_unlock_key` | password non-empty, vault_id 16 bytes | output len == output_len | Beta |
| `derive_vkek` | muk 32 bytes | output len == 32 | Beta |
| `build_aad_v1` | all id fields 16 bytes | output len == 74 | Beta |
| `derive_subkey` | root_prk 32 bytes | output len == 32 | Beta |
| TLV parser | input len ≥ 7 (min TLV) | no out-of-bounds access | Beta |

---

## Level 4: Creusot / Why3 / Coq (Research)

### What it does

Creusot compiles Rust to Why3. Full deductive proofs are written in
Why3 or verified interactively using Coq or Alt-Ergo. This is the
strongest form of formal verification available for Rust.

### When to use

Only for single, critical, rarely-changing functions where:
- Kani and Prusti verification exists and passes
- An independent expert has reviewed and agreed the function is worth full verification
- Budget for expert-hours is available

### Current status

No Creusot targets defined. This is research-phase work.

### Resources

- Creusot: https://github.com/creusot-rs/creusot
- Why3: https://why3.lri.fr
- Requires: Rust nightly, Why3, Coq or Alt-Ergo

---

## Relationship to Other Verification Methods

```
Mathematical verification is NOT a replacement for:

  Test vectors        → implementation produces expected outputs
  Miri                → no undefined behavior at runtime
  Fuzzing             → no crash on malformed input
  External audit      → human expert review of logic and design

Mathematical verification IS a complement:

  Const generics      → compiler proves length invariants
  Kani                → Z3 proves bounded correctness properties
  Prusti              → deductive proofs of function contracts
  Creusot             → full mathematical proofs for selected functions

Together these form overlapping layers of assurance.
No single layer catches everything.
```

---

## Agent Rules Summary

```
Level 1 — always:
  Use Key<N> types, never raw [u8; N] or Vec<u8> for fixed-length secrets

Level 2 — for every security-critical function in arcanum-crypto:
  Write at least one Kani harness using kani::any() for inputs
  Gate with #[cfg(kani)] — never in production binary
  Add TODO markers for harnesses not yet implemented

Level 3 — Beta phase:
  Add Prusti annotations to key derivation and parser functions
  Gate with #[cfg_attr(prusti, requires(...))]

Level 4 — Research:
  Only with human approval and expert support
```
