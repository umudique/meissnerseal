# Arcanum

A local-first secrets vault designed for the post-quantum transition.

Arcanum encrypts secrets on disk with a layered key hierarchy — Argon2id passphrase hardening, HKDF-derived session subkeys, and XChaCha20-Poly1305 authenticated encryption. The vault format and key hierarchy are designed from the start to accommodate hybrid KEM envelopes (X-Wing: X25519 + ML-KEM-768) when sync and transfer land in the next milestone. No cloud, no sync in MVP-0 — just a sealed vault on your filesystem.

> **Alpha software.** Do not store real secrets. The vault format is not stable before v1.0 and no external security audit has been completed.

---

## Why

Most secrets managers treat post-quantum as a future retrofit. Arcanum treats it as an architecture constraint: the key hierarchy, vault format, and planned envelope layer are all specified before implementation — not patched in later. The tradeoffs and rejections are in the ADR log.

---

## Cryptography

```
Passphrase + vault_id
  →  Argon2id (m=64 MiB, t=3, p=1)
  →  MUK  →  HKDF  →  VKEK
  →  AEAD-unwrap  →  VaultRootKey (stored encrypted in vault header)
  →  HKDF-Expand × 7  →  session subkeys
     (item-wrap, metadata, audit, export, sync, device, recovery)

Item encryption:  XChaCha20-Poly1305 under item_wrap_key-derived REK
```

Post-MVP-0 sync and transfer envelopes will use X-Wing hybrid KEM (X25519 + ML-KEM-768; IETF draft, ML-KEM standardized in FIPS 203). See ADR-027.

---

## What works in MVP-0

Local vault operations only:

```
arcanum init              # create a new vault
arcanum add <label>       # store a secret
arcanum get <id>          # retrieve a secret
arcanum list              # list items (no secrets printed)
arcanum lock              # explicit lock
arcanum export <file>     # encrypted portable bundle
arcanum import <file>     # restore from bundle
```

---

## Build

Requires Rust stable (1.78+).

```bash
git clone https://github.com/umudique/arcanum
cd arcanum
cargo build --release -p arcanum-cli
./target/release/arcanum init
```

No binary releases yet.

---

## Roadmap

| Milestone | Scope |
|-----------|-------|
| MVP-0 *(now)* | Local vault, CLI, HKDF key hierarchy, export/import |
| MVP-1 | Device pairing, encrypted sync, X-Wing envelope, recovery |
| Beta | External security audit, stable vault format, binary releases |
| v1.0 | Pure PQC transition, formal verification gates complete |

---

## Design

Decision-log driven. Every non-obvious choice has an ADR:

- Cryptographic primitives — ADR-001, ADR-015, ADR-027
- Vault format — `specs/`
- Threat model — `docs/security_engineering_protocol.md`
- Formal verification — ADR-005, ADR-015

---

## Workspace

```
crates/
  arcanum-core/         vault engine, item store, export/import
  arcanum-crypto/       AEAD, KDF, HKDF, RNG primitives
  arcanum-pqc/          ML-KEM, ML-DSA, hybrid key derivation
  arcanum-security/     secret lifecycle, redaction, hardware adapter
  arcanum-ffi/          FFI boundary
  arcanum-cli/          CLI (binary: arcanum)
  arcanum-sync-server/  encrypted blob sync server (post-MVP-0)
fuzz/                   cargo-fuzz targets
specs/                  protocol and cryptographic specifications
docs/                   architecture decisions, ADR log, operations
test-vectors/           deterministic cryptographic test vectors
```

---

## Security

See [SECURITY.md](SECURITY.md) for scope and reporting.

---

## License

Source code: [Apache-2.0](LICENSE)  
Documentation: [CC BY 4.0](docs/LICENSE-docs)  
Contributions: DCO (`Signed-off-by` in commit message)
