# Security Policy

## Supported Versions

Arcanum is pre-release software. No version is suitable for storing real secrets yet.

| Version | Supported |
|---|---|
| 0.x (alpha) | Security reports accepted; no CVE assignment until beta |

## Reporting a Vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Use **[GitHub Private Security Advisory](https://github.com/umudique/arcanum/security/advisories/new)** to report vulnerabilities confidentially.

We aim to:
- Acknowledge receipt within 48 hours
- Provide an initial assessment within 7 days
- Coordinate disclosure with a 90-day window

## Scope

MVP-0 implements local-only vault operations. Reports are accepted for:

- Vault format parsing, encryption, and integrity verification
- Key derivation (Argon2id) and key hierarchy (MEK, WRK, item keys)
- X-Wing hybrid encryption (X25519 + ML-KEM-768)
- CLI secret handling: passphrase input, argv safety, secret zeroization
- Export/import bundle confidentiality and integrity

Not yet implemented — out of scope until the relevant milestone:
- Sync protocol and device authentication (post-MVP-0)
- Transfer envelope handling (post-MVP-0)
- Recovery mechanisms (MVP-1)

Always out of scope:
- Physical side-channel attacks (power, EM, fault injection)
- Fully compromised endpoint or kernel-level malware
- Social engineering

## Security Warnings

- **Alpha software. Do not store real secrets.**
- Vault format stability is not guaranteed before v1.0; no automatic migration.
- Cryptographic layer uses X-Wing hybrid (X25519 + ML-KEM-768); pure post-quantum
  primitives are planned for a future milestone.
- No external security audit has been completed.
