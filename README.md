# Arcanum

**Local-first critical secrets vault with hybrid post-quantum-ready transfer.**

> **Alpha software. Do not store real secrets yet.**

Arcanum stores and transfers high-value secrets — seed phrases, SSH keys, API tokens, recovery codes, encrypted file bundles — using conservative local-first encryption and hybrid post-quantum-ready sharing protocols.

## Status

Pre-development. Architecture and cryptographic design are complete. Implementation has not started.

## Architecture

See [`docs/`](docs/) for architecture documents and [`specs/`](specs/) for protocol specifications.

The platform is built on:
- Conservative data-at-rest cryptography (Argon2id, XChaCha20-Poly1305, HKDF)
- Hybrid post-quantum-ready transfer (X25519 + ML-KEM-768)
- Local-first, zero-knowledge design
- Fuzz-tested parsers and test-vector-driven cryptographic flows

## Workspace

```
crates/
  arcanum-core/       — vault engine, item store, transfer/sync protocols
  arcanum-crypto/     — AEAD, KDF, HKDF, RNG primitives
  arcanum-pqc/        — ML-KEM, ML-DSA, hybrid key derivation
  arcanum-security/   — secret lifecycle, redaction, hardware adapter
  arcanum-ffi/        — Flutter/native host FFI boundary
  arcanum-cli/        — developer CLI (binary: arcanum)
  arcanum-sync-server/— encrypted blob sync server
fuzz/                 — cargo-fuzz targets
specs/                — protocol and formal specifications
docs/                 — architecture decisions and operations
test-vectors/         — deterministic cryptographic test vectors
```

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## License

AGPL-3.0-or-later
