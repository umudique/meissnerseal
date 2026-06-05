# ADR-005: Staged Formal Methods Roadmap

**Date:** 2025-06
**Status:** Accepted

## Context

Formal verification tools (ProVerif, TLA+, Tamarin, Kani, Creusot/Coq) can verify
different properties at different costs. Committing to all tools simultaneously is
not credible for a small team.

## Decision

Staged commitment by MVP phase:

| Priority | Tool | Scope | Phase |
|---:|---|---|---:|
| Required | ProVerif | Transfer protocol secrecy/authentication | MVP-2 |
| Required | TLA+ | Sync state machine, version vectors | MVP-3 |
| Beta | Tamarin | Device pairing, revocation propagation | Beta |
| Beta | Kani | Selected Rust parsing invariants | Beta |
| Research | Creusot/Coq | High-assurance Rust logic | Research |

## Rationale

- ProVerif is well-understood for protocol secrecy/authentication verification;
  good tooling for X25519+ML-KEM hybrid transfer
- TLA+ is appropriate for sync state machines; version vectors and tombstone
  propagation are state-machine problems
- Tamarin requires more expertise; deferred to beta when device pairing is stable
- Kani (Rust bounded model checking) useful for invariant tests; deferred until
  parsing and key-state code stabilizes
- Creusot/Coq is high-effort; reserved for future high-assurance work

## Consequences

- Formal verification must not be marketed as covering the entire product
- Only verified protocols/modules with published models can be claimed as "formally verified"
- Models live in `specs/formal/` and must include a README explaining scope and how to run
