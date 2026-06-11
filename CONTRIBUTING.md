# Contributing to MeissnerSeal

MeissnerSeal is a security-critical project. Contributions are welcome but must meet
higher-than-average scrutiny for correctness, security, and test coverage.

---

## Before Contributing

- Read the [architecture overview](docs/architecture/overview.md)
- Read the [cryptographic design](specs/crypto/crypto_design.md)
- Read the [threat model](specs/security/threat_model.md)
- Understand the [ADRs](docs/adr/) relevant to your area

---

## Security-Sensitive Contributions

### Cryptographic code

- Never implement cryptographic primitives from scratch
- All changes to `meissnerseal-crypto` or `meissnerseal-pqc` require explicit review
  from a maintainer with cryptographic background
- New cryptographic operations require test vectors
- New AEAD usages require nonce policy review

### Parser changes

- Every new parser or parser change requires a fuzz target update
- Parsers must fail closed — no partial output on malformed input
- Parser fuzzing must run before merge for MVP-0+ code

### Secret handling

- Secrets must use `SecretBytes` or equivalent wrapper types
- `Debug` and `Display` on secret types must be redacted
- No secrets through CLI arguments (use stdin/prompt/file descriptors)
- No secrets in logs, analytics, crash reports, or test output

### FFI changes

- FFI memory ownership must be explicit and auditable
- Changes to `meissnerseal-ffi` require review of lifetime and cleanup semantics
- Dart/Flutter code must not store plaintext in widget state, providers, or route args

---

## Unsafe Rust Policy

- `unsafe` code requires justification in a comment
- `unsafe` in cryptographic crates requires maintainer approval
- `cargo audit` and `cargo deny` must pass before merge

---

## Testing Requirements

| Change Type | Required Tests |
|---|---|
| New cryptographic operation | Unit test + test vector |
| New parser | Unit test + fuzz target |
| New secret-handling code | Redaction test + memory hygiene review |
| Protocol change | Negative test (downgrade, replay, corruption) |
| Sync state change | Property-based test |

---

## Commit Style

- Use conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `test:`
- Reference relevant ADR or spec in commit body for significant changes
- Sign commits on release branches

---

## Reporting Security Issues

Do **not** open public issues for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for the disclosure process.
