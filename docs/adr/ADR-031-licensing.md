# ADR-031 — Project Licensing

**Status:** Accepted  
**Date:** 2026-06-11  
**Deciders:** Core team  

---

## Context

Arcanum is a local-first post-quantum secrets vault intended as an open
research artefact. The licensing decision must balance three objectives:

1. **Research openness** — the codebase should be freely inspectable,
   forkable, and citable by the academic and security research community.
2. **Ecosystem compatibility** — the Rust ecosystem and downstream tooling
   expect well-known, unambiguous licences.
3. **Future commercial optionality** — premium layers (sync, device
   transfer, managed services) built on top of the core may be offered
   under separate commercial terms at a later stage. The core licence must
   not foreclose this path.

---

## Decision

### Source code — Apache-2.0

All source code in `crates/**`, `fuzz/**`, `test-vectors/**`, and
repository tooling is licensed under the **Apache License, Version 2.0**.

### Documentation and specifications — CC BY 4.0

All prose in `docs/**` and `specs/**` is licensed under
**Creative Commons Attribution 4.0 International (CC BY 4.0)**.

---

## Alternatives Considered

### MIT

Simpler and more permissive than Apache-2.0. Rejected because it provides
no patent grant: a contributor could submit code covering a patented
technique and later assert that patent against users. In a cryptographic
project — especially one targeting post-quantum primitives — this risk is
non-trivial. Apache-2.0 includes an explicit, irrevocable patent licence
from each contributor, closing this vector at no cost to openness.

### Apache-2.0 OR MIT (dual)

Standard Rust ecosystem dual licence. Rejected for simplicity: offering
both lets downstream choose MIT and bypass the Apache-2.0 patent clause,
which is the primary reason to choose Apache-2.0 over MIT. A single
Apache-2.0 licence achieves the same openness with stronger protections.

### AGPL-3.0

Would require any network-accessible service built on Arcanum to release
its source code. Rejected because it conflicts with objective 3: future
commercial layers would be forced open, eliminating the option to offer
proprietary managed services. It also reduces adoption in enterprise and
research contexts where AGPL is routinely excluded by legal policy.

### BSL (Business Source Licence)

Converts to open-source after a defined period. Rejected because it is
not an OSI-approved licence, which creates friction for academic citation,
package registries, and enterprise review. The research-openness objective
requires an unambiguous open-source licence from day one.

---

## Consequences

- `LICENSE` file at repository root: Apache-2.0 full text.
- `docs/LICENSE-docs` file: CC BY 4.0 full text.
- Each source file carries an SPDX header: `SPDX-License-Identifier: Apache-2.0`.
- Each documentation file carries: `SPDX-License-Identifier: CC-BY-4.0`.
- Future commercial products built on Arcanum core operate under separate
  licences in separate repositories; the core licence is not affected.
- Contributor workflow: DCO (`Signed-off-by`) is sufficient at current
  project scale. A CLA may be introduced if relicensing becomes necessary;
  that decision will be recorded in a separate ADR.
- Trademark: "Arcanum" is not yet registered. Apache-2.0 §6 restricts use
  of the project name for endorsement without permission. Formal trademark
  registration should be pursued before any public commercial offering.
