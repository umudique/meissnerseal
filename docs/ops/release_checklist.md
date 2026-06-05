# Arcanum Release Security Checklist

---

## Alpha Release

- [ ] `cargo check` passes (all crates)
- [ ] `cargo test` passes
- [ ] `cargo audit` passes (no known vulnerabilities)
- [ ] `cargo deny` passes (license, duplicate, banned crate policy)
- [ ] Threat model draft published
- [ ] Cryptographic design document published
- [ ] Vault format spec published
- [ ] "Alpha — do not store real secrets" banner visible in CLI and UI
- [ ] Responsible disclosure policy (SECURITY.md) in repo
- [ ] No plaintext secrets in argv accepted by CLI
- [ ] Vault file encrypted at rest (verified by test)
- [ ] Vault format has test vectors

---

## Beta Release

All Alpha requirements, plus:

- [ ] Parser fuzz targets implemented and run in CI
- [ ] Transfer envelope fuzz target completed
- [ ] Signed releases (GPG or sigstore)
- [ ] Checksums (SHA256) published with each release artifact
- [ ] SBOM generated (cargo-cyclonedx or cargo-sbom)
- [ ] Reproducible build target defined
- [ ] Transfer protocol specification published
- [ ] ProVerif model for transfer protocol (draft)
- [ ] External protocol review initiated
- [ ] Dependency risk register maintained
- [ ] Unsafe Rust policy documented

---

## Production Release

All Beta requirements, plus:

- [ ] All fuzz targets in CI (including sync envelope)
- [ ] Signed releases required (no unsigned artifacts published)
- [ ] External security audit completed (focused on core + transfer)
- [ ] Audit findings addressed or documented with mitigations
- [ ] Sync protocol specification published
- [ ] TLA+ model for sync state machine
- [ ] Reproducible builds verified
- [ ] Key management policy documented (signing key rotation)
- [ ] Incident response process documented and tested

---

## Enterprise Release

All Production requirements, plus:

- [ ] Pentest completed
- [ ] Audit report published or available to enterprise customers
- [ ] SOC2 readiness evaluated
- [ ] Admin console security reviewed
- [ ] Audit log schema reviewed (no secrets in logs)
- [ ] RBAC policy tested
- [ ] Enterprise deployment guide published
