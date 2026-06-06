# Contract: arcanum-crypto

**Version:** 0.1.0
**API Status:** Unstable  
**Spec authority:** specs/crypto/crypto_design.md  
**ADRs:** ADR-011 (RustCrypto), ADR-013 (OS CSPRNG), ADR-014 (noise hierarchy)

---

## Public API Surface

```
aead::   encrypt(key, plaintext, aad) -> Result<(Ciphertext, XChaCha20Nonce)>
         decrypt(key, nonce, ciphertext, aad) -> Result<Plaintext>
         generate_nonce() -> XChaCha20Nonce        // OS CSPRNG, non-overridable

argon2:: derive(password, vault_id, params) -> Result<MasterUnlockKey>
         derive_vkek(master_unlock_key, vault_id) -> Result<VaultKeyEncKey>

hkdf::   extract(salt, ikm) -> Prk
         expand<const N>(prk, info) -> Result<Key<N>>
         derive_subkey(root_prk, purpose, vault_id, aead_id) -> Result<Key>

rng::    random_bytes(len) -> Vec<u8>            // OS CSPRNG only
         random_key() -> [u8; 32]
         random_nonce_xchacha20() -> [u8; 24]

subtle:: ct_eq(a: &[u8], b: &[u8]) -> Choice    // constant-time comparison

zeroize:: (re-exported types and derive macros)
```

---

## Guarantees

```
[G-01] Nonce generation is always OS CSPRNG. Callers cannot supply nonces
       to AEAD encrypt/decrypt in production builds.

[G-02] All AEAD operations authenticate the associated data.
       A wrong or absent AAD always causes decryption to return Err.

[G-03] All types holding secret material implement Zeroize + ZeroizeOnDrop.
       Memory is cleared when the type is dropped.

[G-04] All secret types have redacted Debug implementations.
       No secret value appears in any formatted output.

[G-05] Argon2id parameters are always passed explicitly.
       No hardcoded parameter values in the implementation.

[G-06] HKDF info strings are deterministic ASCII text.
       vault_id is encoded as lowercase hex (32 chars).
       aead_id is encoded as decimal string.

[G-07] All error paths return Err. No partial output on failure.
```

---

## Anti-Guarantees

```
[A-01] Does NOT prevent access by local malware or kernel-level compromise.

[A-02] Does NOT provide power analysis, EM, or fault injection resistance.
       See ADR-014 for side-channel protection hierarchy.

[A-03] Does NOT guarantee swap or hibernation memory protection.

[A-04] Does NOT implement any custom cryptographic algorithm.

[A-05] Does NOT provide Dart/Flutter memory safety guarantees.
       Dart heap is not within this crate's trust boundary.
```

---

## Preconditions (callers must ensure)

```
[P-01] vault_id passed to argon2::derive and hkdf functions is the canonical
       128-bit vault UUID, not a derived or truncated value.

[P-02] AAD passed to aead::encrypt and aead::decrypt is the canonical
       construction from specs/protocol/vault_format_v1.md §7.

[P-03] key passed to aead functions is 32 bytes and derived from this crate's
       key derivation APIs, not from external sources.
```

---

## Invariants

```
[I-01] This crate never calls network APIs, filesystem APIs, or UI APIs.

[I-02] This crate never logs, prints, or writes secret values to any output.

[I-03] Every public function that takes secret input documents it as
       a SecretBytes or equivalent wrapper type.
```

---

## Dependencies and Expectations

```
argon2          RustCrypto. Audited. Delegates to argon2 reference impl.
chacha20poly1305 RustCrypto. Reviewed. AES-NI optional backend.
aes-gcm         RustCrypto. Reviewed. Constant-time claims documented.
hkdf            RustCrypto. Reviewed. Straightforward RFC 5869.
sha2            RustCrypto. Reviewed.
rand            getrandom feature. Delegates to OS kernel entropy.
zeroize         RustCrypto. Audited (iqlusion 2020).
subtle          dalek-cryptography. Reviewed constant-time library.
bech32          BIP-173/350 reference implementation.
```

---

## Miri Status

This crate must pass `cargo +nightly miri test -p arcanum-crypto` on every change.
Miri failures are release blockers.
