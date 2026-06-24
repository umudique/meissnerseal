<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-037: ProVerif Symbolic Model — Scope and Limitations (MVP-2)

**Status:** Accepted  
**Date:** 2026-06-18  
**Related:** ADR-005 (formal methods roadmap), ADR-024 (Kani scope),
             ADR-015 (mathematical verification strategy),
             ADR-035 (UG combiner hybrid KEM),
             specs/protocol/transfer_profile_v1.md §8,
             specs/security/security_assurance.md §5

---

## Context

ADR-005 established ProVerif as the required tool for transfer protocol formal
verification at MVP-2, with output artifact `specs/formal/transfer_protocol.pv`.
It does not specify what the symbolic model proves, what it explicitly does not
prove, or how it relates to the computational security argument (CryptoVerif,
FORMAL-2).

Left unspecified, the ProVerif result can be misread in two directions: as a
stronger guarantee than the Dolev-Yao model provides (a false assurance), or
as too weak to be worth the effort (an unjustified dismissal). Neither is
correct. This ADR closes the gap in the same way ADR-024 closed the analogous
gap for Kani harnesses.

The transfer protocol is `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1` as
specified in ADR-035 and `specs/protocol/transfer_profile_v1.md`. The ProVerif
model must cover the four security properties stated in spec §8.

---

## Decision

### 1. Model scope

The ProVerif model reasons about the transfer protocol in the **symbolic
(Dolev-Yao) model**: cryptographic primitives are treated as ideal black boxes
with perfect secrecy and authenticity. The adversary controls the network and
can intercept, replay, reorder, inject, and block messages, but cannot invert
a hash, forge a MAC, or break an ideal cipher without the key.

The model covers:

- The message-level structure of the transfer envelope
  (`TransferEnvelope` per spec §2)
- Key derivation at the protocol channel level — the hybrid combiner is
  abstracted as a single idealized operation that produces a fresh symmetric
  key known only to the two parties
- The transcript hash binding (spec §4) — modeled as a commitment that
  binds all named protocol parameters
- The four security properties in spec §8 (see §2 below)

### 2. Properties to verify

All four must produce `RESULT ... is true.` in the ProVerif output:

| Property | ProVerif query |
|---|---|
| **Secrecy** — transfer payload is secret against a passive or active network adversary | `not attacker(payload[])` |
| **Authentication** — only the intended recipient can derive the transfer key | `inj-event(recipientAccepts(eid,th,k)) ==> inj-event(senderSent(eid,th,k))` |
| **Replay protection** — a previously accepted envelope_id cannot be reused | `event(replayBlocked(eid)) ==> event(recipientAcceptsEnvelope(eid))` |
| **Downgrade resistance** — attacker cannot substitute a weaker transfer_profile_id | protocol step rejects unknown profile; modeled as a guard before key derivation |

### 3. What the symbolic model does not prove

The Dolev-Yao model treats all primitives as ideal. It therefore does not
prove — and must not be claimed to prove — the following:

| Limitation | Explanation |
|---|---|
| **Computational hardness** | The symbolic model does not prove that breaking X25519 requires solving CDH, or that breaking ML-KEM requires solving MLWE. These are assumed, not verified. |
| **IND-CCA2 of the hybrid combiner** | The UG combiner's security reduction (ADR-035) is not expressed in ProVerif. It is a computational argument about the combination of a DH-based KEM and an IND-CCA2 PQC KEM. |
| **Side-channel resistance** | The model has no notion of timing, power, or memory access patterns. |
| **Implementation correctness** | The ProVerif model is a design-level artifact. A correct model does not imply a correct Rust implementation. |
| **Forward secrecy lifetime** | The model verifies key freshness per session but does not reason about long-term key compromise windows. |
| **Relay server behaviour** | The relay is modeled as an untrusted forwarder. Server-side rate limiting, TTL enforcement, and log hygiene are outside the model. |
| **Unbounded concurrent replay** | The replay property is proved in a bounded single-session model: one accept followed by one replay attempt. Unbounded concurrent sessions (`!Recipient`) trigger ProVerif table over-approximation that breaks injective correspondence. The `accepted_envelope` table mechanism is witnessed; concurrent replay is complementarily covered by Q2's injectivity over `(eid, th, k)` combined with the freshness of `envelope_id` from `new`. |

These limitations are not defects. They reflect the inherent scope of symbolic
analysis. The computational security argument is addressed by FORMAL-2
(CryptoVerif, post-MVP-2), which provides reduction-based proofs under DDH,
ML-KEM IND-CCA2, and PRF assumptions.

### 4. Model structure requirements

The ProVerif model at `specs/formal/transfer_protocol.pv` must:

- Declare channels, types, and events consistent with the transfer spec
- Abstract each cryptographic primitive as a function with the minimal
  equational theory required: a KEM as `encap/decap` with the cancellation
  equation, HKDF as a pseudorandom function, AEAD as `senc/sdec` with
  decryption-inverse axiom
- Define the sender and recipient processes from spec §3–4
- State each of the four queries above and verify all four pass
- Include a `README` comment block at the top explaining scope, how to run,
  and the ProVerif version used: `proverif transfer_protocol.pv`
- Not model anything outside `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1`
  — no classical-only fallback (there is none), no v2 profile

### 5. Verification command

```
eval $(opam env) && proverif specs/formal/transfer_protocol.pv
```

Expected output: four lines of the form `RESULT ... is true.`  
Any `RESULT ... cannot be proved.` or `false` is a blocking failure.

### 6. Assurance claim boundary

Per `specs/security/security_assurance.md §3.2`:

> "Formal verification — Only for the exact protocols/modules modeled and
> published."

The ProVerif result supports the claim: **"the transfer protocol design is
free of logical protocol attacks under the Dolev-Yao adversary model."**

It does not support: "the transfer protocol is computationally secure,"
"the implementation is correct," or "the protocol is secure against a
quantum adversary at the computational level." These claims require
FORMAL-2, implementation review, and the existing ML-KEM security argument
(ADR-012, ADR-034, ADR-035) respectively.

---

## Alternatives Considered

**Use Tamarin instead of ProVerif:**  
Tamarin is more expressive (multiset rewriting, diff-equivalence) and could
model the device pairing flow alongside the transfer protocol. Rejected for
MVP-2 because ADR-005 already committed to Tamarin for device pairing at
Beta, and using two tools for overlapping scope at the same milestone
increases maintenance cost without proportionate gain. ProVerif's applied
pi-calculus is a better fit for the session-based transfer flow.

**Model the hybrid combiner in full equational detail:**  
Full UG combiner modeling would require expressing the hash-everything IKM
construction as a multi-argument pseudorandom function. The symbolic model
cannot distinguish this from a single idealized KEM in the properties that
matter here (secrecy, authentication). The computational distinction is
CryptoVerif's job, not ProVerif's. Rejected as false precision in the wrong
model.

**Skip ProVerif and rely on the CryptoVerif proof alone (FORMAL-2):**  
CryptoVerif proofs are harder to audit, take longer to complete, and are
written after the symbolic proof establishes the protocol structure is
sound. The symbolic proof is a prerequisite for the computational proof,
not a substitute for it. Rejected.

---

## Development and Review Protocol

ProVerif model development follows a two-phase gate, enforced by
`AGENTS.md §12`.

**Phase 1 — Structure only (human-approved before Phase 2):**
- Type declarations, channel declarations, free names
- Function signatures with equational theory
- Event declarations
- The four query statements (ADR-037 §2) — stated but not yet proved
- Process sketches: guard order and event placements, no full bodies
- proverif is NOT run in Phase 1

The human reviews Phase 1 to confirm: queries correctly express the four
properties, equational theory looks sound, guard order matches spec §5.

**Phase 2 — Full model and proof:**
- Complete process bodies
- proverif run: all four RESULT lines must be `true`
- No query may be trivially true (see §3 anti-patterns below)

**Formal Review Agent gate (after Phase 2):**

Before FORMAL-1 is marked done, Formal Review Agent evaluates:
1. Equational theory faithfulness
2. Query non-triviality
3. Spec fidelity (transcript fields, guard order)
4. Adversary model correctness
5. Coverage completeness (all four spec §8 properties)
6. Abstraction calibration

Approval must be `approved` or `approved_with_reservations`.
`needs_revision` or `rejected` returns to Phase 2.

**Anti-patterns that invalidate a query:**
- Dead code in the else branch that is never reached (query holds vacuously)
- Over-constrained process that only accepts honest-sender messages
- Event fired unconditionally before the guard it is meant to witness
- Private name that is provably unreachable from the net channel

---

## Consequences

- `specs/formal/transfer_protocol.pv` is the required artifact for
  the MVP-2 formal verification gate (GATE-MVP2)
- The model is a design-level artifact; it does not substitute for
  implementation testing, Miri, or the security review of `meissnerseal-core`
- ProVerif 2.05 via OPAM is the required tool version; version pinned in
  `docs/ops/dependency_risk_register.md`
- FORMAL-2 (CryptoVerif) remains the required follow-on step for a
  computational security claim; it is unblocked by the ProVerif proof
- Any future modification to the transfer protocol (new profile, new
  algorithm, envelope field addition) requires updating the ProVerif model
  before the change can be declared formally verified
