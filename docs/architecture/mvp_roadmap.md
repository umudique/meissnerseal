# Arcanum — MVP Roadmap

**Document status:** Planning reference  
**Spec version:** v4.0

---

## 1. MVP Philosophy

Arcanum should avoid becoming a broad password manager too early. The MVP must prove the unique security thesis:

> "Arcanum can locally store critical secrets and transfer them between devices or recipients using a documented hybrid post-quantum-ready protocol without exposing plaintext to any server."

---

## 2. MVP Priority

| Priority | MVP | Reason |
|---:|---|---|
| 1 | MVP-0 Core + CLI | Establishes trust boundary |
| 2 | MVP-2 Transfer | Strongest differentiation |
| 3 | MVP-1 Desktop UI | Makes product demonstrable |
| 4 | MVP-3 Self-hosted Sync | Commercial foundation |
| 5 | MVP-4 Browser Extension | Useful, not the main wedge |
| 6 | MVP-5 Managed Sync | First SaaS revenue |
| 7 | MVP-6 Teams / Enterprise | Long-term revenue layer |

The strongest early demo is:
> "A seed phrase transferred between devices using local-first encryption and hybrid post-quantum-ready key exchange, with no server able to decrypt it."

---

## 3. MVP Definitions

### MVP-0 — Cryptographic Core and CLI

**Target:** 10–16 weeks  
**Objective:** Build the minimal trusted foundation.

**Included:**
- Rust workspace, `arcanum-core`, `arcanum-crypto` crates
- Local vault file format (`ARCANUM_FORMAT_V1`)
- Master password unlock with `KDF_ARGON2ID_V1`
- AEAD encryption with `AEAD_XCHACHA20_POLY1305_V1`
- Item types: Password, SeedPhrase, SshPrivateKey, ApiToken, SecureNote
- CLI: `arcanum init|add|list|get|export|import|lock`
- CLI operational safety: no plaintext in argv, stdin/prompt/fd input
- Encrypted `.arcexp` export/import by default
- Unit tests, property-based tests, test vectors
- Initial threat model and cryptographic design document

**Excluded:** Browser extension, sync, mobile, enterprise, autofill

**Success criteria:**
- Vault data encrypted at rest with versioned format
- CLI cannot leak secrets through argv, logs, or shell history
- Core crypto functions have test vectors
- Public warning: "Alpha software. Do not store real secrets yet."

---

### MVP-1 — Desktop Security Preview

**Target:** 8–12 weeks after MVP-0  
**Objective:** Usable desktop application around the local vault core.

**Included:**
- Flutter desktop app (Windows, Linux, macOS if practical)
- Rust core through FFI with handle-and-lease model
- Secret item creation/editing, encrypted file attachments
- Clipboard timeout, auto-lock, local search
- Encrypted vault backup/export using `.arcexp`
- Signed development builds, alpha banner
- Crash-safe write strategy

**Excluded:** Browser autofill, sync, mobile, team sharing

---

### MVP-2 — Arcanum Transfer

**Target:** 6–8 weeks after MVP-1  
**Objective:** Secure transfer using hybrid post-quantum-ready key agreement.

**Included:**
- Device identity keys, recipient public key export
- QR/manual pairing flow
- `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1` profile
- Transfer envelope format, encrypted file bundles
- CLI: `arcanum transfer create|receive`, `arcanum device pair`
- Desktop transfer UI, offline bundle mode
- Optional relay server prototype
- Replay protection, expiring transfer metadata
- Transfer protocol specification
- **ProVerif model for transfer secrecy/authentication**

**Success criteria:**
- Transfer server cannot decrypt contents
- Downgrade attacks addressed in protocol transcript
- Transfer envelopes fuzz-tested
- Protocol reviewed (external review begins parallel to development)

---

### MVP-3 — Self-Hosted Encrypted Sync

**Target:** 4–6 months after MVP-0  
**Objective:** Encrypted multi-device sync with zero-knowledge principle.

**Included:**
- Sync server with device registry, encrypted blob storage
- Client-side version vectors for conflict detection
- User-mediated conflict resolution (no auto-merge for critical secrets)
- Device approval flow, signed revocation events
- Device-signed canonical request authentication
- Version vector pruning with compaction checkpoints
- Docker Compose deployment, PostgreSQL/SQLite mode
- Sync protocol specification
- **TLA+ model for sync state machine**

**Excluded:** Managed SaaS billing, enterprise SSO, SCIM

---

### MVP-4 — Browser Extension Preview

**Target:** 5–7 months after MVP-0  
**Objective:** Browser integration without becoming an autofill-first manager.

**Included:**
- Chrome/Firefox WebExtension, TypeScript UI
- Native messaging bridge with allowlisted extension IDs
- Search, copy; manual fill; explicit user approval
- No automatic background exfiltration
- Native messaging parser fuzz targets

---

### MVP-5 — Managed Sync Beta

**Target:** 8–12 months after MVP-0  
**Objective:** First commercial SaaS layer.

**Included:**
- Managed encrypted sync service, subscription billing
- Signed releases, SBOM, incident response process
- **External security review of sync/transfer protocol**
- Rate limiting, abuse prevention, operational monitoring

---

### MVP-6 — Teams and Enterprise

**Target:** 12–18 months after MVP-0  
**Objective:** Controlled team sharing and governance.

**Included:**
- Team vaults, role-based access controls
- Admin-managed device approval, encrypted audit events
- Emergency recovery policy, organization key rotation
- SSO prototype, self-hosted enterprise deployment

---

## 4. Security Deliverables by Phase

| Phase | Product | Security Deliverable | Minimum Evidence |
|---:|---|---|---|
| MVP-0 | Core + CLI | Secret wrappers, Argon2id, AEAD, HKDF, initial fuzz targets | Unit/property tests, test vectors, threat model draft |
| MVP-1 | Desktop | Clipboard timeout, auto-lock, memory-only UI, crash-safe writes | Integration tests, UI security checklist |
| MVP-2 | Transfer | Hybrid profile, transcript binding, replay protection | Transfer spec, vectors, fuzzing, ProVerif model |
| MVP-3 | Sync | Sync envelopes, device approval, version-vector conflict model | Sync spec, envelope fuzzing, TLA+ model |
| MVP-4 | Browser | Native bridge, minimal permissions, explicit approval | Permission review, native messaging parser tests |
| MVP-5 | Managed Sync | Signed releases, SBOM, incident process, external review | Release checklist, SBOM, audit notes |
| MVP-6 | Teams | Audit events, policy controls, admin governance | Audit schema, policy tests, enterprise review |

---

## 5. Corporate Phases

| Phase | Deliverables | Outcome |
|---|---|---|
| 1 — Foundation | Rust core, CLI, vault, threat model, crypto design, fuzzing setup | Credible open-source security foundation |
| 2 — Differentiated Demo | Secure transfer, desktop UI, device pairing, public protocol spec | Strong portfolio and contributor-attracting release |
| 3 — Alpha Community | Public alpha, responsible disclosure, signed builds | Trust-building open-source project |
| 4 — Sync Beta | Self-hosted sync, managed sync, billing, external protocol review | First viable commercial SaaS layer |
| 5 — Teams/Enterprise | Team vaults, admin console, audit logs, SSO, enterprise guide | B2B revenue opportunity |

---

## 6. Business Model

| Product Layer | Pricing | Purpose |
|---|---|---|
| Local vault core | Free / open source | Trust, adoption, transparency |
| CLI and desktop app | Free / open source | Developer adoption |
| Secure transfer basic | Free / open source | Differentiated wedge |
| Self-hosted sync | Free / community | Technical credibility |
| Managed encrypted sync | Subscription | Consumer/pro revenue |
| Team vaults | Subscription | Commercial expansion |
| Enterprise admin console | Enterprise license | B2B revenue |
| Audit logs and policy controls | Enterprise | Compliance and governance |
| SSO / SCIM | Enterprise | Enterprise readiness |

**First paid product:** Arcanum Sync Pro — managed encrypted sync and secure transfer history.  
**Second paid product:** Arcanum Teams — shared vaults, device approvals, audit trails, policy controls.

---

## 7. Risk Register

| Risk | Severity | Mitigation |
|---|---|---|
| Perceived as another password manager | High | Position around critical secrets and secure transfer |
| PQC marketing overclaim | High | Use precise "post-quantum-ready" language |
| Crypto design mistakes | Critical | Conservative primitives, external review |
| Sync metadata leakage | High | Metadata minimization |
| Browser extension attack surface | High | Delay until core stable; use native bridge |
| Seed phrase liability | Critical | Alpha warnings, audit before production |
| Dependency compromise | High | Supply-chain controls |
| AI-generated code vulnerabilities | High | Human review, tests, fuzzing |
| Scope creep | High | Prioritize core + transfer before password manager |
