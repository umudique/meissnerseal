# Arcanum — Agent Reference

**Read this file first. Every agent reads this before anything else.**

---

## 1. Project

Arcanum is a local-first critical secrets vault with hybrid post-quantum-ready
transfer. It stores seed phrases, SSH keys, API tokens, and other secrets that
are difficult or impossible to rotate. A bug in Arcanum can cause permanent,
unrecoverable data loss or secret exposure.

There is no experienced security engineer reviewing every line in real time.
The protocols and tools in this file are the substitute.

---

## 2. Crate Map

```
arcanum-crypto/       Cryptographic primitives only.
                      Argon2id, XChaCha20-Poly1305, HKDF, RNG.
                      No application logic.
                      API Status: Unstable

arcanum-pqc/          Post-quantum primitives only.
                      ML-KEM-768, ML-DSA, hybrid key derivation.
                      No application logic.
                      API Status: Unstable

arcanum-security/     Secret lifecycle enforcement.
                      Zeroization, redaction, hardware adapter,
                      session policy, audit guard.
                      API Status: Unstable

arcanum-core/         Vault engine, item store, transfer protocol,
                      sync protocol, device manager, recovery manager.
                      Calls arcanum-crypto and arcanum-pqc.
                      Never implements crypto directly.
                      API Status: Unstable

arcanum-ffi/          FFI boundary to Flutter/Dart.
                      Handle-and-lease model only.
                      Exposes VaultSessionHandle, SecretViewHandle.
                      API Status: Unstable

arcanum-cli/          Developer CLI binary (arcanum).
                      No plaintext secrets in argv.
                      Secret input via stdin, prompt, or file descriptor.
                      API Status: Unstable

arcanum-sync-server/  Encrypted blob relay.
                      Zero plaintext access.
                      Device-signed request authentication.
                      API Status: Unstable

fuzz/                 cargo-fuzz targets. Workspace root.
                      One target per parser.

specs/                Protocol and cryptographic specifications.
                      Source of truth for all cryptographic behavior.

docs/                 Architecture, ADRs, agent prompts, ops.

test-vectors/         Known-answer test vectors.
                      Must be cross-verified with independent implementation.
```

**API Status values:** `Unstable` | `Stable` | `Deprecated`

A crate's API Status is in its CONTRACT.md header. A dependent crate must not
begin implementation until all its dependencies have `API Status: Stable`.

---

## 3. Mandatory Algorithm

Every agent that writes or modifies code follows this sequence.
No step may be skipped. See full detail in:
`docs/security/security_engineering_protocol.md`

```
1. Read this file (AGENTS.md)
2. Read role prompt (docs/agents/AGENT_PROMPT_TEMPLATE.md)
3. Read CONTRACT.md of every crate being modified
4. Read relevant spec files
5. Declare scope (Section 10)
6. Check dependency gate (Section 11)
7. Write precondition / postcondition / invariant
8. Write test first — Phase 1 (Section 12)
9. [Human reviews Phase 1 — for Crypto and Core agents]
10. Write implementation — Phase 2
11. Run static tools (Section 5)
12. Write completion report (Section 13)
```

---

## 4. Absolute Security Invariants

These rules have no exceptions. Any code that violates them must not be committed.

```
CRYPTO (see also: docs/security/standards_conformance.md — CNSA 2.0 §2)
  [ ] No custom cryptographic primitives
  [ ] No custom RNG — OS CSPRNG only (ADR-013; SP 800-90B delegated to OS)
  [ ] No unauthenticated encryption
  [ ] All AEAD operations use canonical AAD construction
  [ ] No caller-supplied nonces outside test modules
  [ ] No == comparison on secret values — use subtle::ConstantTimeEq
  [ ] Fixed-length crypto values use Key<N> types, never raw [u8;N] or Vec<u8>
  [ ] Every security-critical fn in arcanum-crypto has a #[cfg(kani)] harness
  [ ] New algorithm selections checked against CNSA 2.0 mapping table before adoption

MATHEMATICAL VERIFICATION (see ADR-015, docs/development/mathematical_verification.md)
  [ ] Level 1: Key<const N: usize> encodes length at compile time
  [ ] Level 2: Kani harnesses prove bounded properties (length, no overflow)
  [ ] Level 3: Prusti annotations on key derivation and parsers (Beta)
  [ ] Proof code is gated #[cfg(kani)] / #[cfg(prusti)] — never in prod binary

MEMORY
  [ ] All secret types implement Zeroize + ZeroizeOnDrop
  [ ] All secret types have redacted Debug implementation
  [ ] No plaintext secrets in log output at any level
  [ ] No plaintext secrets in error messages
  [ ] No plaintext secrets in test fixtures or test output
  [ ] No long-lived plaintext in Flutter/Dart widget state

PARSER
  [ ] Every parser fails closed — no partial output on malformed input
  [ ] Every parser has a fuzz target
  [ ] Unknown critical fields are rejected, not ignored

PROTOCOL
  [ ] Algorithm identifiers are authenticated in every protocol
  [ ] Downgrade attempts are rejected before any decryption
  [ ] Expired envelopes are rejected
  [ ] Replay protection is enforced

UNSAFE RUST
  [ ] Every unsafe block has a // SAFETY: comment explaining why it is sound
  [ ] No unsafe in arcanum-crypto or arcanum-pqc without maintainer review
  [ ] cargo geiger output is reviewed on every unsafe addition

SCOPE
  [ ] Agents work only within their assigned crate boundaries
  [ ] Agents do not modify specs/ or docs/ unless their role permits
  [ ] Agents do not modify another crate's CONTRACT.md
```

---

## 5. Static Tool Invocation

Run these commands in order after every code change.
All must pass before the task is complete.

```bash
# Format
cargo fmt --all

# Type check
cargo check --workspace --all-targets

# Lint — warnings are failures
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Tests
cargo test --workspace

# Dependency security
cargo audit
```

Additional tools for cryptographic crates (arcanum-crypto, arcanum-pqc,
arcanum-security, arcanum-ffi):

```bash
# Undefined behavior detection
cargo +nightly miri test -p <crate-name>

# Bounded model checking — proves length and bounds properties (ADR-015)
cargo kani --package <crate-name>
```

---

## 6. Forbidden Actions

```
NEVER write a cryptographic primitive from scratch
NEVER use a custom RNG implementation
NEVER log, print, or write a secret value at any level
NEVER return partial plaintext on decryption failure — return Err
NEVER skip the test-first step for cryptographic or parser code
NEVER modify a crate outside your assigned scope
NEVER commit code that fails cargo clippy -- -D warnings
NEVER commit code that fails cargo audit
NEVER use == to compare secret values
NEVER derive Debug on a type that holds secret material
NEVER place plaintext secrets in route arguments, global state, or analytics
NEVER change a dependency version without human approval
NEVER begin implementation on a crate before its dependencies are Stable
```

---

## 7. Vocabulary

```
Profile ID        Numeric identifier for a cryptographic algorithm version.
                  Example: AEAD_XCHACHA20_POLY1305_V1 = 0x0001

Vault Root Key    Master symmetric key derived from master password.
                  Never stored in plaintext. Wrapped by VKEK.

Record Encryption Key (REK)
                  Fresh random key per encrypted record revision.
                  Never reused across revisions.

Transcript hash   SHA-256 hash over all protocol parameters.
                  Prevents downgrade and algorithm substitution attacks.

Fail closed       Returning Err without producing any partial result
                  when a security check fails.

Handle-and-lease  FFI pattern: Dart stores opaque handle, not plaintext.
                  Rust manages secret memory. Lease expires after TTL.

Version vector    Map<DeviceId, Counter> for concurrent edit detection.

Tombstone         Encrypted delete marker. Replaces deleted records.

Contract          CONTRACT.md file in each crate. Defines public API,
                  guarantees, anti-guarantees, and preconditions.

API Status        Stability marker in CONTRACT.md header.
                  Unstable: API may change. Stable: API is committed.
                  Deprecated: do not add new dependencies on this API.

Phase 1           Test-only phase: preconditions + tests, no implementation.
                  Human reviews before Phase 2 begins.

Phase 2           Implementation phase: writes code to pass Phase 1 tests.
```

---

## 8. Spec Authority

When implementation and spec conflict, the spec is correct.
Fix the implementation to match the spec.
If the spec is wrong, open an ADR — do not silently diverge.

```
specs/crypto/crypto_design.md          → all cryptographic operations
specs/protocol/vault_format_v1.md      → vault binary format
specs/protocol/transfer_profile_v1.md  → transfer protocol
specs/protocol/sync_profile_v1.md      → sync protocol
specs/protocol/recovery_kit_v1.md      → recovery encoding
specs/security/threat_model.md         → adversary model
specs/security/security_assurance.md   → control matrix, claims
docs/adr/                              → architecture decisions
```

---

## 9. Role Directory

Full prompts are in `docs/agents/AGENT_PROMPT_TEMPLATE.md`.

```
Crypto Agent          arcanum-crypto only
PQC Agent             arcanum-pqc only
Core Agent            arcanum-core only
Security Agent        arcanum-security only
FFI Agent             arcanum-ffi only
CLI Agent             arcanum-cli only
Sync Server Agent     arcanum-sync-server only
Fuzz Agent            fuzz/fuzz_targets/ only
Test Vector Agent     test-vectors/ only
Spec Agent            specs/ and docs/ only — no code
Architect Agent       docs/ and specs/ only — decisions
Security Review Agent read-only evaluator — no writes
Consistency Agent     read-only consistency checker — no writes
```

---

## 10. Scope Declaration

Before writing any code, the agent declares its scope in the completion report.
This declaration is verified against `git diff` when the task ends.

```
SCOPE DECLARATION
  Will modify:    crates/arcanum-crypto/src/aead.rs
                  crates/arcanum-crypto/src/lib.rs
  Will read:      specs/crypto/crypto_design.md
                  crates/arcanum-crypto/CONTRACT.md
  Will NOT touch: crates/arcanum-core/**
                  specs/**
                  docs/**
```

If a file outside the declaration is modified, human approval is required
before committing. Scope violations are not self-authorized.

---

## 11. Dependency Gate

A crate must not begin implementation until all its dependencies
have `API Status: Stable` in their CONTRACT.md.

```
Dependency order:

  arcanum-crypto    must be Stable before:
                      arcanum-pqc, arcanum-security start

  arcanum-pqc       must be Stable before:
                      arcanum-core starts (transfer module)

  arcanum-security  must be Stable before:
                      arcanum-core, arcanum-ffi start

  arcanum-core      must be Stable before:
                      arcanum-ffi, arcanum-cli, arcanum-sync-server start
```

To mark a crate Stable, update its CONTRACT.md header:
```
**API Status:** Stable
```
This requires human approval.

---

## 12. Phase Gate

Applies to: Crypto Agent, PQC Agent, Core Agent, Security Agent.
Other agents may use a single phase.

**Phase 1 — Test and Precondition only**

The agent writes only:
- `/// # Contract` block (precondition / postcondition / invariant)
- Test vector reference or test vector file entry
- `proptest` property test (rule, not example)
- Fuzz target skeleton (if the task involves a parser)

Run: `cargo test --workspace` — tests must compile, may fail.
Do not write implementation code in Phase 1.

Human reviews Phase 1 output → approves or requests revision.
Implementation does not begin until Phase 1 is approved.

**Phase 2 — Implementation**

After Phase 1 approval, the agent writes the implementation.
All tests written in Phase 1 must pass.
Run all static tools (Section 5).
Write completion report (Section 13).

**Milestone gate — after Phase 2 completion of each crate**

Before a crate can be marked `API Status: Stable`, two agents must run in order:

```
1. Consistency Agent
   Checks spec → implementation alignment.
   Verdict must be "Clear" (no Critical findings).

2. Security Review Agent
   Evaluates the implementation against security invariants.
   Approval recommendation must be "approved" or "approved_with_reservations".
   "needs_revision" or "rejected" blocks Stable marking.

3. Human reviews both reports → approves Stable marking in CONTRACT.md.
```

The number of Phase 1 / Phase 2 cycles per crate is not fixed.
If Phase 1 review requests revision, Phase 1 repeats before Phase 2 begins.
If Security Review returns "needs_revision", Phase 2 repeats for the flagged items.

```
Full crate lifecycle:

  Phase 1 → human approval
      ↓
  Phase 2 → completion report
      ↓
  Consistency Agent → Clear verdict
      ↓
  Security Review Agent → approved / approved_with_reservations
      ↓
  Human → CONTRACT.md: API Status: Stable
```

MVP-0 complete gate: Consistency Agent runs across the full repository
(arcanum-crypto + arcanum-security + arcanum-core) before MVP-0 is declared done.

---

## 13. Completion Report

Every agent produces this report at the end of every task.
No task is complete without a completion report.

```markdown
## Completion Report

**Role:** [agent role]
**Task:** [task description]

**Scope Declaration (actual):**
- Modified: [list of files actually modified]
- Read: [list of files read]

**Phase 1 output:** [test / property / fuzz skeleton — or N/A]
**Phase 1 approved by:** [human name or "N/A"]

**Tests written:**
- [test name]: [what it tests]

**Tool results:**
- cargo fmt:    [PASS / FAIL]
- cargo check:  [PASS / FAIL]
- cargo clippy: [PASS (N warnings) / FAIL]
- cargo test:   [PASS (N tests) / FAIL]
- cargo audit:  [PASS / FAIL]
- Miri:         [PASS / FAIL / N/A]

**CONTRACT.md changes:** [None / describe changes]
**Spec deviations:** [None / describe and open ADR]
**Open questions:** [None / list]
```

---

## 14. Commit Protocol

Every agent commit must follow `docs/development/git_workflow.md` exactly.
Key rules summarized here:

```
TYPE PREFIXES
  feat:     new capability or module
  fix:      bug correction
  docs:     documentation, specs, ADRs, CONTRACT.md
  test:     test additions with no production code change
  ci:       CI/CD and hook changes
  chore:    toolchain, scaffolding, dependency updates
  security: closes a security finding or removes a forbidden pattern

SUBJECT LINE
  [ ] Starts with type prefix and colon (feat:, fix:, docs:, etc.)
  [ ] Imperative mood — "add", "fix", "remove", not "added", "fixes"
  [ ] No capital letter after the colon
  [ ] No period at the end
  [ ] 50 chars ideal, 72 chars hard limit
  [ ] No "complete", "finish", "done", "WIP", "various changes"

BODY
  [ ] Blank line between subject and body
  [ ] Explains WHY the change was made, not WHAT the code does
  [ ] References the relevant spec file or ADR
  [ ] Lines wrapped at 72 characters

FOOTER (optional)
  [ ] Closes/Fixes/Refs #N if applicable
  [ ] BREAKING CHANGE: <description> if stable API changes

SECURITY
  [ ] No real secret values anywhere in the commit message or test fixtures
  [ ] No real private keys, vault files, or credentials
```

A commit that fails any of the above must be amended before pushing.

---

## 15. Tool Failure Protocol

When a static tool fails, follow this protocol exactly.

**`cargo check` fails:**
```
1. Diagnose the compile error.
2. Fix and re-run.
3. If the error originates from a spec violation, escalate to Architect Agent.
4. After 2 failed fix attempts, report task failure to human.
   Do not proceed with broken compilation.
```

**`cargo clippy -D warnings` fails:**
```
1. Fix all warnings.
2. If using #[allow(...)], add // REASON: comment explaining why.
3. If a lint appears to be a false positive, do NOT self-approve.
   Add to the open questions section of the completion report.
   Human decides whether to add a workspace-level exception.
```

**`cargo audit` fails:**
```
If the output contains a vulnerability:
  → STOP. Do not commit.
  → Report to human immediately.
  → Agent cannot change dependency versions unilaterally.
  → Human decides: update, replace, or accept with documented justification.

If the output contains an "unmaintained" warning:
  → Log in completion report open questions.
  → Does not block the task.
```

**`cargo +nightly miri test` fails:**
```
→ CRITICAL BLOCKER.
→ Record the exact location of the undefined behavior.
→ Do not proceed with implementation.
→ Human treats this at CVE severity.
→ No further commits to the affected crate until resolved.
```

**`cargo fuzz run` produces a crash:**
```
→ RELEASE BLOCKER.
→ The crash artifact is saved to fuzz/artifacts/<target>/.
→ Do not delete crash artifacts.
→ No further changes to the affected parser until the crash is reproduced
  and a fix is confirmed by running the fuzz target again without crash.
→ Report to human immediately.
```
