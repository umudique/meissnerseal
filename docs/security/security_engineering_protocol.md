# Arcanum Security Engineering Protocol

**Status:** Authoritative reference — all agents and contributors must follow  
**Read by:** Every agent before writing any code  
**Related:** [AGENTS.md](../../AGENTS.md), [security_assurance.md](../../specs/security/security_assurance.md)

---

## 1. Purpose

Arcanum is a security-critical platform. There is no experienced security engineer
reviewing every line in real time. This protocol is the substitute: a set of
mandatory disciplines and automated tools that enforce correct behavior whether
the author is a human or an AI agent.

Every agent and contributor must follow this protocol completely.
There are no exceptions for "simple" changes.

---

## 2. Mandatory Agent Algorithm

Every agent that writes or modifies code must follow this sequence in order.
No step may be skipped.

```
STEP 1 — Context Loading
  Read AGENTS.md
  Read role-specific prompt from docs/agents/AGENT_PROMPT_TEMPLATE.md
  Read CONTRACT.md of every crate being modified
  Read every spec file relevant to the task
  Read existing test vectors if the task touches cryptographic operations

STEP 2 — Precondition / Postcondition / Invariant
  Before writing any implementation, document in code:

  // PRECONDITION:  what must be true before this function is called
  // POSTCONDITION: what is guaranteed to be true after this function returns
  // INVARIANT:     what is always true about this type or module

  These are not optional comments. They are the specification the
  implementation will be measured against.

STEP 3 — Test First (choose one path)

  Path A — Cryptographic operation:
    The test vector must exist in test-vectors/ before implementation.
    The implementation is correct when it reproduces the known answer.
    Cross-verification with Python or SageMath is required.

  Path B — Behavioral invariant or property:
    Write a proptest property test before implementation.
    The property must express a rule, not an example.
    Example of a rule: "encrypt then decrypt equals identity for all inputs"
    Example of NOT a rule: "encrypt('hello') returns [0x9a, ...]"

  Path C — Parser:
    Write the fuzz target skeleton in fuzz/fuzz_targets/ before the parser.
    The fuzz target must assert fail-closed behavior.
    Reject cases must be tested before accept cases.

  Path D — State machine:
    Write property tests for every state transition before implementation.
    Invalid transitions must be unreachable at the type level where possible.

STEP 4 — Implementation
  Write the implementation.
  The implementation must satisfy the preconditions and postconditions
  written in Step 2.
  The implementation must pass all tests written in Step 3.

STEP 5 — Static Verification (mandatory, run in this order)
  cargo fmt --all
  cargo check --workspace --all-targets
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo test --workspace
  cargo audit

  All commands must pass with zero errors and zero warnings.
  A clippy warning is treated as a build failure.

STEP 6 — Completion Check
  Every test written in Step 3 passes.
  Every precondition and postcondition is documented in code.
  CONTRACT.md is updated if the public API changed.
  No plaintext secret appears in any test fixture, log, or output.
```

---

## 3. Tool Inventory

### Layer 1 — Compile Time (every commit, seconds)

| Tool | Command | Catches |
|---|---|---|
| rustc | `cargo check --workspace --all-targets` | Type errors, missing bounds |
| rustfmt | `cargo fmt --all` | Formatting |
| clippy | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Bad practices, potential bugs |

### Layer 2 — Static Analysis (every commit, seconds to minutes)

| Tool | Command | Catches |
|---|---|---|
| cargo-audit | `cargo audit` | Known CVEs in dependencies |
| cargo-deny | `cargo deny check` | License violations, banned crates, duplicates |
| cargo-geiger | `cargo geiger` | Unsafe code inventory |

### Layer 3 — Dynamic Analysis / Testing (every commit)

| Tool | Command | Catches |
|---|---|---|
| cargo test | `cargo test --workspace` | Functional failures, property violations |
| proptest | embedded in `cargo test` | Invariant violations, edge cases |

### Layer 4 — Miri (per-crate, on change)

Miri detects undefined behavior. It is slow — run only on changed crates.

| Crate | When to run Miri | Command |
|---|---|---|
| arcanum-crypto | Every change | `cargo +nightly miri test -p arcanum-crypto` |
| arcanum-pqc | Every change | `cargo +nightly miri test -p arcanum-pqc` |
| arcanum-ffi | Every change | `cargo +nightly miri test -p arcanum-ffi` |
| arcanum-security | Every change | `cargo +nightly miri test -p arcanum-security` |

### Layer 5 — Fuzzing (periodic, security lab)

| Tool | Command | Catches |
|---|---|---|
| cargo-fuzz | `cargo fuzz run <target> -- -max_total_time=60` | Parser crashes, panics, OOM |
| AFL++ | `cargo afl fuzz -i corpus -o findings ./target` | Alternative coverage |

Run smoke fuzz (60 seconds per target) before every MVP preview release.
Run extended fuzz (24+ hours) before every public beta.

### Layer 6 — Memory Sanitizers (CI, periodic)

```bash
# AddressSanitizer
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test --target x86_64-unknown-linux-gnu

# MemorySanitizer  
RUSTFLAGS="-Z sanitizer=memory" cargo +nightly test --target x86_64-unknown-linux-gnu

# ThreadSanitizer
RUSTFLAGS="-Z sanitizer=thread" cargo +nightly test --target x86_64-unknown-linux-gnu
```

Run on every PR for cryptographic crates. Run on all crates before release.

### Layer 7 — Cryptographic Verification (milestone-gated)

| Tool | Purpose | Phase |
|---|---|---|
| dudect | Timing side-channel detection | Beta |
| BINSEC/checkct | Binary-level constant-time verification | Beta |
| SageMath | Independent test vector cross-verification | MVP-2 |
| lattice-estimator | ML-KEM parameter security | MVP-2 |

### Layer 8 — Mathematical Verification (ADR-015)

Four levels of mathematical verification, applied progressively.
See `docs/development/mathematical_verification.md` for the full guide.

| Level | Tool | Scope | Phase |
|---|---|---|---|
| 1 | Const generics (`Key<N>`) | Length invariants at compile time | MVP-0 |
| 2 | Kani | Bounded properties: length, no overflow, no panic | MVP-0+ |
| 3 | Prusti | Hoare triples on key derivation and parsers | Beta |
| 4 | Creusot / Coq | Full deductive proofs for selected functions | Research |

### Layer 9 — Protocol Formal Verification (milestone-gated)

| Tool | Scope | Phase |
|---|---|---|
| ProVerif | Transfer protocol secrecy and authentication | MVP-2 |
| TLA+ | Sync state machine, version vectors | MVP-3 |
| Tamarin | Device pairing, revocation propagation | Beta |

---

## 4. Design by Contract

Every security-critical function must document its contract before implementation.

### Format

```rust
/// # Contract
///
/// ## Preconditions
/// - `nonce` must be exactly 24 bytes (XChaCha20-Poly1305 requirement)
/// - `key` must be derived from OS CSPRNG, never from caller-supplied data
/// - `aad` must be the canonical AAD construction (see vault_format_v1.md §7)
///
/// ## Postconditions
/// - Returns `Err` if AEAD authentication fails — never returns partial plaintext
/// - Returns `Err` if nonce length does not match AEAD profile
/// - On success, returned bytes are guaranteed to be the decrypted plaintext
///
/// ## Invariants
/// - This function never logs, prints, or exposes the key or plaintext
/// - Nonce generation is internal and cannot be overridden by the caller
```

### Rules

- Postconditions must cover ALL error paths, not just the happy path
- Invariants must state what this function never does (logging, exposure)
- A function without a contract may not be merged into a cryptographic crate

### Rust Enforcement Layers

```
Level 1 — Type system:    invalid states unrepresentable at compile time
                          (Key<N> const generics encode length as a fact)
Level 2 — debug_assert!:  checked in tests, zero cost in release
Level 3 — proptest:       probabilistic verification of rules
Level 4 — Kani:           bounded mathematical proof (all inputs in scope)
Level 5 — Prusti:         deductive Hoare-triple proof (Beta)
Level 6 — Creusot/Coq:    full deductive proof (Research)
```

---

## 5. Test Hierarchy

```
Test Vector (known-answer)
  → Cryptographic operations only
  → Must be cross-verified with independent implementation
  → File lives in test-vectors/ before implementation starts

Property Test (proptest / quickcheck)
  → Behavioral rules and invariants
  → "encrypt then decrypt = identity" not "encrypt('x') = [0x9a]"
  → Written before implementation

Unit Test
  → Specific behavior confirmation
  → Written with implementation

Fuzz Test (cargo-fuzz)
  → Parser and protocol boundary
  → Skeleton written before parser implementation
  → Must assert fail-closed behavior

Integration Test
  → Cross-crate behavior
  → Full flow testing (vault create → unlock → add → get)

Negative Test
  → Every error path must have a test
  → Downgrade, replay, corruption, wrong key, expired envelope
  → Written before or with implementation
```

---

## 6. Memory Safety Requirements

These rules apply to every crate. No exceptions.

### Secret Types

Every type that holds secret material must:
- Use `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop`
- Implement `Debug` manually with `[REDACTED]` output
- Not implement `Clone` unless explicitly justified in a comment
- Not implement `Display`
- Not implement `Serialize` unless the output is always encrypted

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}
```

### Forbidden Patterns

```
FORBIDDEN: logging or printing secret values at any log level
FORBIDDEN: storing secret values in struct fields that derive Debug
FORBIDDEN: returning owned plaintext from long-lived sessions
FORBIDDEN: placing plaintext in error messages
FORBIDDEN: using == for secret comparison (use subtle::ConstantTimeEq)
FORBIDDEN: using String for secret values (use SecretBytes or equivalent)
```

### FFI Boundary

- Dart/Flutter heap is not part of the trusted memory boundary
- Secrets crossing FFI must use the handle-and-lease model (ADR-004)
- Every FFI call that touches secret material must document cleanup semantics

---

## 7. Constant-Time Requirements

These rules apply to all code in arcanum-crypto and arcanum-pqc.

### Rules

- No branch on secret data (if/match on a secret value is forbidden)
- No memory access indexed by secret data
- All secret comparisons use `subtle::ConstantTimeEq`
- All secret selections use `subtle::ConditionallySelectable`
- All length comparisons use `subtle::ConstantTimeEq` on byte arrays

### Verification

- `subtle` crate is the only approved constant-time primitive library
- Miri must pass for all cryptographic crates
- dudect verification is required before beta release

---

## 8. Side-Channel Protection Hierarchy

```
Level 1 — Primary (mandatory):
  Constant-time implementation
  No secret-dependent branches or memory accesses

Level 2 — Secondary (where applicable):
  Algorithmic masking (input randomization before crypto operation)
  Point blinding for ECC operations

Level 3 — Tertiary (defense-in-depth, documented limitations):
  Noise / dummy operations
  Random delays
  WARNING: statistical averaging removes noise.
           Noise does NOT provide mathematical guarantees.
           Level 3 is only valid on top of Level 1 and Level 2.
```

---

## 9. Backdoor Prevention

```
No custom RNG — OS CSPRNG only (ADR-013)
  Eliminates Dual EC DRBG class of backdoor

Nothing-up-my-sleeve constants
  HKDF info strings are ASCII text, not opaque numbers
  All constants are derivable from documented inputs

Reproducible builds
  Binary must be reproducible from source
  Auditors can verify binary matches source

Supply chain
  cargo audit: CVE scanning
  cargo deny: policy enforcement
  cargo vet: dependency trust chain
  Multiple independent reviewers for cryptographic code

Formal verification
  Protocol logic verified by ProVerif / Tamarin / TLA+
  Rust invariants verified by Kani where feasible
```

---

## 10. Quick Reference — Minimum Gates Per Role

| Role | Minimum before completion |
|---|---|
| Crypto Agent | fmt + check + clippy + test + audit + Miri |
| PQC Agent | fmt + check + clippy + test + audit + Miri |
| Core Agent | fmt + check + clippy + test + audit |
| Security Agent | fmt + check + clippy + test + audit + Miri |
| FFI Agent | fmt + check + clippy + test + audit + Miri |
| CLI Agent | fmt + check + clippy + test + audit |
| Sync Server Agent | fmt + check + clippy + test + audit |
| Fuzz Agent | cargo check (fuzz crate) + verify target compiles |
| Test Vector Agent | cross-verification with independent implementation |
| Spec Agent | no cargo tools — consistency check with existing specs |
