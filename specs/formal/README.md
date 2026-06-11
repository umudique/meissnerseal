<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Arcanum Formal Specifications

This directory contains formal verification models for Arcanum's security protocols.
These models verify logical properties of the protocol design at a symbolic level.

**Important scope note:** Formal verification here operates on mathematical models,
not on Rust source code. A passing formal model proves that the *protocol design*
has the stated properties under the Dolev-Yao adversary model. It does not prove
that the Rust implementation is bug-free. The implementation gap is closed by:
- Test vectors (known-answer tests)
- Miri (undefined behavior)
- Fuzzing (malformed input)
- External security audit

---

## Models

| File | Tool | Protocol | MVP Phase | Status |
|---|---|---|---|---|
| `transfer_protocol.pv` | ProVerif | Transfer secrecy, authentication, replay, downgrade | MVP-2 | Skeleton |
| `sync_state_machine.tla` | TLA+ | Sync version vectors, conflict preservation, compaction | MVP-3 | Skeleton |
| `device_pairing.spthy` | Tamarin | Device pairing MITM, revocation propagation | Beta | Skeleton |

---

## ProVerif — `transfer_protocol.pv`

### What ProVerif proves

ProVerif uses the symbolic (Dolev-Yao) adversary model: the adversary controls
the network, can intercept and modify messages, but cannot break cryptographic
primitives. Under this model, the transfer protocol model must prove:

```
Secrecy:
  The transfer payload is secret from the network adversary.
  Even if the relay server is compromised, the adversary cannot learn
  the plaintext transferred between two honest devices.

Authentication:
  The recipient can verify that the envelope was created by the claimed sender.
  An adversary cannot forge a valid transfer envelope.

Replay resistance:
  A previously accepted envelope_id cannot be replayed to produce a
  second successful decryption.

Downgrade resistance:
  An adversary cannot cause two honest parties to use a weaker algorithm
  than both support. Algorithm identifiers in the transcript are authenticated.
```

### What ProVerif does not prove

- Side-channel resistance of the Rust implementation
- Correctness of the ML-KEM library
- Protection against a compromised endpoint
- Anything outside the Dolev-Yao model (power analysis, etc.)

### Installation

```bash
# Debian/Ubuntu
apt-get install proverif

# macOS
brew install proverif

# From source: https://proverif.inria.fr
```

### Running the model

```bash
# When model content is added (MVP-2):
proverif specs/formal/transfer_protocol.pv
```

Expected output when proofs pass:
```
RESULT not attacker(transfer_payload[]) is true.
RESULT inj-event(recv(x,y)) ==> inj-event(sent(x,y)) is true.
```

---

## TLA+ — `sync_state_machine.tla`

### What TLA+ verifies

TLA+ is a specification language for concurrent and distributed systems.
The sync state machine model verifies:

```
Conflict preservation:
  Concurrent edits from two offline devices are never silently discarded.
  The system always preserves both versions until user resolution.

Tombstone propagation:
  A delete event (tombstone) eventually reaches all approved devices,
  even those that were offline at the time of deletion.

Compaction safety:
  Version vector compaction never removes evidence of unresolved conflicts.
  A revoked device's last counter is preserved until all approved devices
  have observed the signed revocation event.

Idempotency:
  Replaying an already-seen revision has no effect on state.

Server reordering:
  Server-side blob reordering does not cause client-side data loss.
```

### Installation

```bash
# Install TLA+ Toolbox (includes TLC model checker):
# https://github.com/tlaplus/tlaplus/releases

# Or use the TLA+ CLI:
# https://github.com/tlaplus/tlaplus

# Java required
java -version
```

### Running the model

```bash
# When model content is added (MVP-3):
# Via TLA+ Toolbox: open sync_state_machine.tla, run TLC model checker

# Via CLI:
java -jar tla2tools.jar specs/formal/sync_state_machine.tla
```

### Scope of TLA+ model

The model abstracts over cryptography (treats encrypted blobs as opaque).
It focuses on the state machine properties: ordering, conflict detection,
tombstone propagation, and compaction correctness.

---

## Tamarin — `device_pairing.spthy`

### What Tamarin proves

Tamarin is more expressive than ProVerif, supporting:
- Mutable state (modeled as facts)
- Complex multi-session protocols
- Accountability properties (who did what)

The device pairing model verifies:

```
MITM resistance:
  An adversary controlling the network cannot complete a pairing between
  two honest devices without one of them detecting the attack (when
  out-of-band verification is performed).

Revocation completeness:
  After a device is revoked, it cannot successfully commit sync state
  or decrypt future sync envelopes.

Concurrent pairing safety:
  Two simultaneous pairing attempts do not interfere with each other
  in a way that grants unauthorized access.
```

### What Tamarin does not prove

- Security of TOFU (trust-on-first-use) pairing without OOB verification.
  TOFU is documented as weaker in the product (ADR, pairing spec).
- Security against a compromised trusted device that was approved before revocation.
  This limitation is documented in the threat model.

### Installation

```bash
# macOS
brew install tamarin-prover

# Linux: build from source
# https://tamarin-prover.com/manual/master/book/002_installation.html

# Requires: Haskell Stack, Maude
```

### Running the model

```bash
# When model content is added (Beta):
tamarin-prover --prove specs/formal/device_pairing.spthy
```

---

## Formal Verification Limitations

All three models operate at the symbolic (Dolev-Yao) level or state machine level.
They share the following limitations:

```
The models do NOT verify:
  ✗ Rust implementation correctness
  ✗ Side-channel resistance
  ✗ Cryptographic primitive security (assumed correct)
  ✗ Protection against a fully compromised endpoint
  ✗ Anything outside the defined adversary model

The models DO verify:
  ✓ Protocol logic: message flow, ordering, authentication
  ✓ Absence of logical attacks: replay, downgrade, MITM
  ✓ State machine invariants: conflict, tombstone, compaction
  ✓ Protocol composition: hybrid KEM security under Dolev-Yao
```

The gap between formal model and implementation is addressed by:
- Test vectors: implementation must reproduce model-consistent outputs
- Miri: no undefined behavior in Rust implementation
- Fuzzing: no crash on malformed protocol inputs
- External security audit: human expert review of implementation

---

## Adding Model Content

When adding content to a model file, follow this process:

1. Read the relevant spec file (transfer_profile_v1.md, sync_profile_v1.md, etc.)
2. Model the protocol faithfully — divergence from the spec is an error
3. State explicitly which security properties are modeled and which are not
4. Add a comment block at the top of the model file describing:
   - Protocol version being modeled
   - Security properties proved
   - Assumptions (e.g., "cryptographic primitives are ideal")
   - Known limitations
5. Run the model checker to verify all stated properties pass
6. Update the Status column in this README from `Skeleton` to `Draft` or `Verified`
7. Human reviews before marking `Verified`
