<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# MeissnerSeal Threat Model

**Status:** Draft — MVP-0  
**Review cadence:** Before each MVP public release  
**Related:** [security_assurance.md](security_assurance.md), [crypto_design.md](../crypto/crypto_design.md)

---

## 1. Assets

| Asset | Sensitivity | Notes |
|---|---|---|
| Master password | Critical | Never stored; only exists transiently during unlock |
| Vault root key | Critical | Wrapped at rest; plaintext only during unlocked session |
| Record encryption keys | Critical | Fresh per revision; wrapped by item key wrapping key |
| Item key wrapping key | Critical | HKDF-derived from vault root key |
| Device signing private key | Critical | Signs pairing transcripts and revocation events |
| Seed phrases | Critical | Unrecoverable if leaked or corrupted |
| SSH private keys | Critical | Unrecoverable if leaked |
| API tokens | Critical | Often non-rotatable or costly to rotate |
| Recovery codes | Critical | Single-use; catastrophic if exposed |
| Recovery kit | Critical | Offline key material; possession may unlock vault |
| `.msexp` export bundles | Critical | Encrypted; passphrase-protected; must not be left unguarded |
| Encrypted vault file (`.msv`) | Sensitive | Offline brute-force target without strong KDF |
| Transfer envelopes (relay) | Sensitive | Opaque to relay; metadata visible |
| Local metadata DB (SQLite) | Sensitive | Device IDs, sync state, timestamps — metadata leakage risk |
| Sync metadata (server) | Sensitive | Blob sizes, timestamps, device IDs visible to server |
| Device public keys | Public, integrity-sensitive | Integrity failure enables pairing MITM |
| Local audit events | Sensitive | Must not contain secret values |

---

## 2. Adversaries

| Adversary | Capability |
|---|---|
| Local malware | Read files, memory, clipboard, screenshots; inject keystrokes |
| Cloud attacker | Compromise sync server or object storage |
| Network attacker | Intercept, replay, or modify traffic |
| Malicious transfer recipient | Replay captured envelope; attempt unauthorized decryption |
| Stolen device attacker | Physical access to vault file and local metadata DB |
| Insider sync admin | Read server metadata, blob sizes, device IDs, timestamps |
| Compromised trusted device | Previously paired device later compromised; possesses sync keys derived before revocation |
| Malicious browser extension | Fake or compromised extension attempting to impersonate MeissnerSeal extension to native host |
| Future quantum attacker | Harvest public-key encrypted material now; decrypt after quantum computer available |
| Supply-chain attacker | Compromise dependencies, CI pipeline, or release artifacts |

---

## 3. Trust Boundaries

| Component | Trusted For | Not Trusted For |
|---|---|---|
| Rust Core (`meissnerseal-core`, `meissnerseal-crypto`, `meissnerseal-pqc`) | Secret lifecycle, cryptographic operations | Nothing excluded |
| OS Secure Storage (Keychain, Keystore, DPAPI) | Device wrapping key storage | Availability on all platforms; absolute hardware guarantee |
| Dart/Flutter heap | Displaying secrets transiently | Zeroization timing; swap/hibernation protection |
| Sync server | Availability, ordering, pagination | Confidentiality, authenticity, key material |
| Relay server | Forwarding encrypted envelopes | Confidentiality, recipient identity, envelope validity |
| Browser extension | User-visible UI | Secret storage, full vault access |
| OS accessibility APIs | — | Completely untrusted; screenshot/keylogging risk documented |
| Network transport (TLS) | Availability, replay protection | Confidentiality of vault plaintext (client-side AEAD provides this) |

---

## 4. In Scope

- Offline vault file theft and brute-force attack
- Sync server compromise (metadata and blob access)
- Network MITM on transfer and sync protocol
- Transfer replay attacks
- Downgrade attacks on protocol negotiation
- Malformed vault file, transfer envelope, and sync envelope parsing
- Accidental plaintext logging (logs, analytics, crash reports)
- Clipboard exposure
- Timing side-channel leakage in cryptographic boundary
- Dependency supply-chain compromise
- Recovery kit theft (printed or file-based)
- Export bundle (`.msexp`) theft from disk
- Browser extension isolation failure (web page attempting native host access)
- Device pairing MITM (without out-of-band verification)
- Unauthorized sync commits from revoked devices

---

## 5. Out of Scope (Early MVP)

The following are documented limitations, not failures:

- Fully compromised OS kernel or endpoint
- Kernel-level malware with ring-0 access
- Hardware implants
- Power analysis (SPA/DPA)
- Electromagnetic side-channel attacks
- Fault injection
- Speculative execution attacks (Spectre/Meltdown variants)
- Coercion attacks (rubber-hose cryptanalysis)
- Malicious operating system
- Malicious or backdoored hardware secure enclave
- Perfect protection against screen capture or accessibility API abuse
- Swap and hibernation memory protection (platform-dependent; documented)
- Protection from secrets already decrypted by a device before revocation

---

## 6. Control-to-Threat Mapping

| Threat | Adversary | Primary Control | Verification |
|---|---|---|---|
| Offline vault theft | Stolen device | Argon2id KDF + AEAD | KDF test vectors, offline attack analysis |
| Vault file tampering | Any | AEAD authentication + AAD binding | AAD mismatch rejection tests |
| Sync server compromise | Cloud attacker | Client-side AEAD, zero-knowledge blobs | Sync spec, server data inventory |
| Network MITM (transfer) | Network attacker | Transcript binding, device signing keys | ProVerif model, negative tests |
| Transfer replay | Malicious recipient | `envelope_id` uniqueness + `expires_at` | Replay rejection tests |
| Protocol downgrade | Network attacker | Algorithm IDs in authenticated transcript | Downgrade test report |
| Malformed parser input | Any / supply-chain | Fail-closed parsers + fuzzing | Fuzz corpus, crash reports |
| Accidental plaintext logging | Internal / malware | Redacted `Debug`, log redaction tests | Snapshot/log test report |
| Clipboard leakage | Local malware | Clipboard timeout + overwrite | UI platform tests |
| Supply-chain compromise | Supply-chain attacker | cargo-audit, cargo-deny, SBOM, signed releases | CI report, release checklist |
| Recovery kit theft | Physical adversary | Argon2id passphrase hardening (optional) + user warning | Recovery kit spec, UX review |
| Export bundle theft | Physical / malware | Encrypted `.msexp` by default, passphrase required | Export vector tests |
| Browser isolation failure | Malicious extension | Extension ID allowlist in native host | Native messaging parser tests |
| Device pairing MITM | Network attacker | QR/OOB fingerprint verification, signed transcript | Pairing spec, Tamarin model |
| Revoked device access | Compromised device | Signed revocation event + sync key rotation | Revocation tests, TLA+ model |
| Argv/shell-history secret leakage | Local malware / accident | No `--secret` flag; clap error output generic; `--stdin` is sole non-interactive mechanism (CONTRACT G-01) | Argv rejection tests, clap error echo tests |
| Timing side-channel | Local malware | Constant-time helpers in crypto boundary | dudect-style tests (Beta) |
| Metadata leakage (server) | Insider admin | Metadata minimization, opaque blob IDs | Server data inventory, contract tests |

---

## 7. User Error and Misuse Cases

These are not adversarial threats but represent failure modes that must be documented
and where possible mitigated in the product:

| Scenario | Risk | Mitigation |
|---|---|---|
| User loses master password with no recovery kit | Vault permanently unrecoverable | Prominent recovery kit creation prompt at init; repeated reminders |
| User stores recovery kit digitally without encryption | Kit becomes a single point of failure | Warn during kit generation; recommend offline physical storage |
| User uses same recovery kit across multiple vaults | Single kit compromise unlocks all vaults | Each vault generates its own `recovery_id`; kits are vault-specific |
| User forgets `.msexp` export bundle passphrase | Export data unrecoverable | Warn that export passphrase is separate and not stored |
| User leaves `.msexp` bundle in cloud storage | Encrypted, but increases attack surface | Warn during export; recommend immediate deletion after use |
| User approves a device without verifying OOB fingerprint | TOFU pairing; weaker security | Label clearly as "unverified pairing" in UI; recommend QR |
| Developer uses `--unsafe-plaintext` import in production | Plaintext secrets written to disk | Flag requires explicit confirmation; warning cannot be suppressed |

---

## 8. Security Claim Boundaries

**MeissnerSeal may claim:**
- Local-first encrypted vault
- Zero-knowledge encrypted sync
- Hybrid post-quantum-ready transfer
- Crypto-agile vault format
- Fuzz-tested parsers (only after fuzz targets run in CI)
- Public threat model

**MeissnerSeal must not claim:**
- Unhackable security
- Military-grade quantum encryption
- Absolute quantum-proof protection
- Resistance to all side channels
- Full production security before external review
- Protection from secrets already decrypted before device revocation

See [security_assurance.md](security_assurance.md) for the full claims matrix with evidence requirements.
