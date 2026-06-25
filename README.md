# MeissnerSeal

A local-first secrets vault designed for the post-quantum transition.

MeissnerSeal encrypts secrets on disk with a layered key hierarchy — Argon2id passphrase hardening, HKDF-derived session subkeys, and XChaCha20-Poly1305 authenticated encryption. The vault format and key hierarchy are designed from the start to accommodate hybrid KEM envelopes (UG combiner: X25519 + ML-KEM-768) when sync and transfer land in the next milestone. No cloud, no sync in MVP-0 — just a sealed vault on your filesystem.

> **Alpha software.** Do not store real secrets. The vault format is not stable before v1.0 and no external security audit has been completed.

---

## Why

Most secrets managers treat post-quantum as a future retrofit. MeissnerSeal treats it as an architecture constraint: the key hierarchy, vault format, and planned envelope layer are all specified before implementation — not patched in later. The tradeoffs and rejections are in the ADR log.

---

## Cryptography

```
Passphrase + vault_id
  →  Argon2id (m=64 MiB, t=3, p=4)
  →  MUK  →  HKDF  →  VKEK
  →  AEAD-unwrap  →  VaultRootKey (stored encrypted in vault header)
  →  HKDF-Expand × 7  →  session subkeys
     (item-wrap, metadata, audit, export, sync, device, recovery)

Item encryption:  XChaCha20-Poly1305 under item_wrap_key-derived REK
```

Post-MVP-0 transfer envelopes use the UG hash-everything combiner (X25519 + ML-KEM-768, HKDF-SHA256; ML-KEM standardized in FIPS 203). See ADR-035.

---

## What works in MVP-0

Local vault operations only:

```
meissnerseal init <path>                              # create a new vault
meissnerseal add --label <label> --kind <kind> --vault <path>   # store a secret
meissnerseal get <item_id> --vault <path>             # retrieve a secret
meissnerseal list <path>                              # list items (no secrets printed)
meissnerseal lock                                     # explicit lock
meissnerseal export --output <file> --vault <path>    # encrypted portable bundle
meissnerseal import --input <file> --vault <path>     # restore from bundle
```

Transfer and device commands are wired in MVP-2:

```
meissnerseal transfer create    # create a transfer envelope
meissnerseal transfer receive   # receive a transfer envelope
meissnerseal device pair        # pair with another device
```

---

## Build

Requires Rust stable (1.78+).

```bash
git clone https://github.com/umudique/meissnerseal
cd meissnerseal
cargo build --release -p meissnerseal-cli
./target/release/meissnerseal init my-vault.msv
```

No binary releases yet.

---

## Roadmap

| Version | Milestone | Scope |
|---------|-----------|-------|
| `0.1.0-alpha` *(now)* | MVP-0 | Local vault, CLI, HKDF key hierarchy, export/import |
| `0.2.0-alpha` | MVP-2 | Hybrid KEM transfer (UG combiner), device identity, transfer envelope |
| `0.3.0-alpha` | MVP-1 | Desktop app, clipboard timeout, auto-lock, FFI |
| `0.4.0-beta` | MVP-3 | Encrypted sync, device approval, TLA+ model |
| `0.5.0-beta` | MVP-4 | Browser extension, native messaging |
| `0.6.0` | MVP-5 | Managed sync, signed releases, external review |
| `0.7.0` | MVP-6 | Teams, enterprise, SSO |
| `1.0.0` | — | Vault format frozen, formal gates complete, pure PQC |

MVP-2 precedes MVP-1: transfer proves the core security thesis (hybrid PQ key agreement between devices, no server decryption). Desktop UI follows once the protocol is demonstrated.

---

## Design

Decision-log driven. Every non-obvious choice has an ADR:

- Cryptographic primitives — ADR-001, ADR-015, ADR-035
- Vault format — `specs/`
- Threat model — `docs/security/security_engineering_protocol.md`
- Formal verification — ADR-005, ADR-015

---

## Workspace

```
crates/
  meissnerseal-core/         vault engine, item store, export/import
  meissnerseal-crypto/       AEAD, KDF, HKDF, RNG primitives
  meissnerseal-pqc/          ML-KEM, ML-DSA, hybrid key derivation
  meissnerseal-security/     secret lifecycle, redaction, hardware adapter
  meissnerseal-ffi/          FFI boundary
  meissnerseal-cli/          CLI (binary: meissnerseal)
  meissnerseal-sync-server/  encrypted blob sync server (post-MVP-0)
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
