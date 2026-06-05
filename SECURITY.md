# Security Policy

## Supported Versions

Arcanum is pre-release software. No version is suitable for storing real secrets yet.

| Version | Supported |
|---|---|
| 0.x (alpha) | Security reports accepted; no CVE assignment until beta |

## Reporting a Vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

**Contact:** [security contact to be added before public release]

We aim to:
- Acknowledge receipt within 48 hours
- Provide an initial assessment within 7 days
- Coordinate disclosure with a 90-day window

## Scope

In scope:
- Vault format parsing and encryption
- Key derivation and hierarchy
- Transfer protocol and envelope handling
- CLI secret handling and argv safety
- Sync protocol and device authentication

Out of scope for MVP:
- Physical side-channel attacks (power, EM, fault injection)
- Fully compromised endpoint / kernel-level malware
- Social engineering

## Security Warnings

- **Alpha software. Do not store real secrets.**
- Vault format may change without migration support before v1.0.
- No external security audit has been completed.
