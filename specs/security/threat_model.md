# Arcanum Threat Model

**Status:** Draft — MVP-0
**Review cadence:** Before each MVP public release

---

## 1. Assets

| Asset | Sensitivity |
|---|---|
| Master password | Critical |
| Vault root key | Critical |
| Item keys (record encryption keys) | Critical |
| Seed phrases | Critical |
| SSH private keys | Critical |
| API tokens | Critical |
| Recovery codes | Critical |
| Recovery kit | Critical |
| Encrypted vault file | Sensitive |
| Sync metadata | Sensitive |
| Device public keys | Public, integrity-sensitive |
| Audit metadata | Sensitive |

---

## 2. Adversaries

| Adversary | Capability |
|---|---|
| Local malware | Read files, memory, clipboard, screenshots |
| Cloud attacker | Compromise sync server or object storage |
| Network attacker | Intercept or modify traffic |
| Malicious recipient | Replay or unauthorized access to transfer |
| Stolen device attacker | Access local vault file |
| Insider admin | Access server metadata |
| Future quantum attacker | Harvest public-key encrypted material for future decryption |
| Supply-chain attacker | Dependency or build compromise |

---

## 3. In Scope

- Offline vault file theft
- Sync server compromise
- Network MITM on transfer and sync
- Transfer replay attacks
- Downgrade attacks on protocol negotiation
- Malformed vault file parsing
- Malformed transfer and sync envelopes
- Accidental plaintext logging
- Clipboard exposure
- Timing side-channel awareness in cryptographic boundary
- Dependency supply-chain risks

---

## 4. Out of Scope (Early MVP)

The following are documented limitations, not failures to address:

- Fully compromised endpoint or kernel
- Kernel-level malware
- Hardware implants
- Power analysis (SPA/DPA)
- Electromagnetic side-channel attacks
- Fault injection
- Speculative execution attacks (Spectre/Meltdown)
- Coercion attacks
- Malicious operating system
- Malicious hardware secure enclave
- Perfect protection against screen capture or accessibility API abuse
- Swap/hibernation memory protection (platform-dependent, documented)

---

## 5. Control-to-Threat Mapping

| Threat | Primary Control | Verification |
|---|---|---|
| Offline vault theft | Argon2id KDF + AEAD | KDF test vectors, offline attack analysis |
| Sync server compromise | Client-side AEAD, zero-knowledge | Sync spec, server data inventory |
| Network MITM (transfer) | Transcript binding, device signing | ProVerif model, negative tests |
| Transfer replay | envelope_id + expires_at | Replay rejection tests |
| Downgrade attack | Algorithm ID in transcript/AAD | Downgrade test report |
| Malformed parser input | Fail-closed parsers + fuzzing | Fuzz corpus, crash reports |
| Accidental plaintext logging | Redacted Debug, log tests | Snapshot/log test report |
| Clipboard leakage | Clipboard timeout | UI platform tests |
| Supply-chain | cargo-audit, cargo-deny, SBOM | CI report |

---

## 6. Security Claim Boundaries

**Arcanum may claim:**
- Local-first encrypted vault
- Zero-knowledge encrypted sync
- Hybrid post-quantum-ready transfer
- Crypto-agile vault format
- Fuzz-tested parsers (after fuzz targets run in CI)
- Public threat model

**Arcanum must not claim:**
- Unhackable security
- Military-grade quantum encryption
- Absolute quantum-proof protection
- Resistance to all side channels
- Full production security before external review

See [security_assurance.md](security_assurance.md) for the full claims matrix.
