# Contract: meissnerseal-pqc

**Version:** 0.1.0
**API Status:** Stable  
**Spec authority:** specs/crypto/crypto_design.md §7, specs/protocol/transfer_profile_v1.md  
**ADRs:** ADR-011 (RustCrypto), ADR-012 (ML-KEM risk), ADR-028 (signature crypto-agility), ADR-034 (RustCrypto ml-kem backend), ADR-035 (UG combiner hybrid KEM), ADR-036 (ML-KEM-768 parameter set)

---

## Public API Surface

```
mlkem::  keypair() -> (MlKemPublicKey, MlKemPrivateKey)
         encapsulate(public_key) -> (MlKemCiphertext, SharedSecret)
         decapsulate(private_key, ciphertext) -> Result<SharedSecret>

hybrid:: x25519_keypair() -> (X25519PrivateKey, X25519PublicKey)

         derive_transfer_key(
           sender_ephemeral_private: &X25519PrivateKey,
           sender_ephemeral_public: &X25519PublicKey,
           recipient_classical_public: &X25519PublicKey,
           pqc_ciphertext: &MlKemCiphertext,
           pqc_shared_secret: &SharedSecret,
           transcript_hash: &[u8; 32],
         ) -> Result<TransferKey>

         receive_transfer_key(
           recipient_classical_private: &X25519PrivateKey,
           recipient_classical_public: &X25519PublicKey,
           sender_ephemeral_public: &X25519PublicKey,
           pqc_ciphertext: &MlKemCiphertext,
           pqc_private_key: &MlKemPrivateKey,
           transcript_hash: &[u8; 32],
         ) -> Result<TransferKey>

mldsa::  SigningAlgorithmId
           Ed25519V1 = 0x0001
           Ed25519MlDsa87HybridV1 = 0x0002

         SigningPublicKey { algorithm_id, public_key_bytes }
         SigningPrivateKey { algorithm_id, private_key_bytes }
         Signature { algorithm_id, signature_bytes }

         sign(private_key, message) -> Result<Signature>
         verify(public_key, message, signature) -> Result<()>
         SigningAlgorithmId::from_u16(u16) -> Result<SigningAlgorithmId>

         SigningError (load-bearing variants — changes are breaking):
           UnknownAlgorithm   — from_u16 received an unregistered algorithm ID
           Unimplemented      — algorithm slot registered but not yet active
           AlgorithmMismatch  — key and signature carry different algorithm IDs
           InvalidKey         — key or public key bytes are malformed/wrong length
           MalformedSignature — signature bytes are wrong length or structurally invalid
           VerificationFailed — signature is well-formed but does not verify

         Status: Ed25519V1 implemented with ed25519-dalek after ADR-020
         approval. Hybrid signing slot is registered but returns
         Unimplemented until PQ signing audit clears a future PQC-4
         implementation.
```

---

## Guarantees

```
[G-01] Hybrid derivation follows
       TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1 exactly.
       Classical: X25519 ephemeral. PQC: ML-KEM-768. KDF: HKDF-SHA256.
       Transcript hash: SHA-256 (32 bytes).

[G-02] ML-KEM decapsulation uses FIPS 203 §6.3 implicit rejection: a tampered
       same-length ciphertext returns Ok with a pseudorandom shared secret, not
       Err. This prevents decryption oracles. The two parties will derive
       different keys and the transfer will fail at the AEAD layer.
       Missing PQC ciphertext in the hybrid envelope causes rejection at the
       hybrid layer (receive_transfer_key). There is no classical-only fallback.

[G-03] Profile mismatch (wrong algorithm ID in transcript) is bound by the
       transcript_hash salt: a mismatched profile produces a different
       transcript_hash, and therefore a different TransferKey that the peer
       cannot reproduce. Explicit rejection of the mismatch occurs at the
       envelope layer (XFER-1); this crate derives a key regardless and does
       not inspect algorithm identifiers directly.

[G-04] All secret key material implements Zeroize + ZeroizeOnDrop.

[G-05] No secret-dependent branches in ML-KEM operations
       (to the extent the underlying library guarantees this).

[G-06] Device signing keys and signatures are algorithm-tagged per ADR-028.
       Verification rejects algorithm mismatches before primitive-specific
       verification. Ed25519V1 is the MVP implementation target. The
       Ed25519+ML-DSA hybrid slot is registered as 0x0002 but fails closed
       with Unimplemented until a PQ signing audit clears integration.
```

---

## Anti-Guarantees

```
[A-01] Does NOT guarantee the ML-KEM library implementation is free of
       side-channel vulnerabilities. Audit status: see ADR-012.

[A-02] Does NOT implement ML-KEM from scratch. Uses an approved library backend.

[A-03] Does NOT provide classical-only fallback when hybrid mode is required.
       Fail closed.

[A-04] Does NOT guarantee symbolic security of ML-KEM itself —
       that is guaranteed by NIST FIPS 203 analysis, not this crate.

[A-05] Does NOT implement ML-DSA signing in MVP-2. The hybrid signing
       algorithm identifier exists only as an agility slot until a future
       audited backend is approved.
```

---

## Verification Status

```
cargo test:    16/16 pass for mlkem:: + hybrid:: + mldsa::, including
               NIST ML-KEM KATs, ADR-035 transfer-hybrid KATs, and ADR-028
               Ed25519V1 signing KATs
Miri:          16/16 pass (2026-06-25, mlkem:: + hybrid:: + mldsa::,
               -Zmiri-strict-provenance -Zmiri-symbolic-alignment-check)
               All Ed25519V1 sign/verify paths verified UB-free.
Kani:          6 harnesses, 6/6 SUCCESS (2026-06-25)
               Note: ML-KEM NTT loops and large Key<N> zeroize drops
               exceed practical unwind budgets — see proofs module.
               mldsa:: has no Kani harnesses yet; length/type proofs
               deferred to a future PQC-4 task.
Fuzz:          Not applicable — no parser surface in mlkem:: or hybrid::
Test vectors:  3/3 pass — NIST ACVP ML-KEM-768 AFT (tcIds 26-28,
               internalProjection.json commit 65370b8).
               test-vectors/mlkem_768_kat_v1.json; nist_kat_decapsulate
               test; Python mlkem_cross_verify.py NIST source check.
               F-20 resolved (commit f4dc008).
               2/2 pass — ADR-035 UG hybrid combiner vectors in
               test-vectors/transfer_hybrid_v1.json; Python
               transfer_hybrid_cross_verify.py recomputes real X25519 and
               HKDF-SHA256.
               2/2 pass — ADR-028 Ed25519V1 signing vectors in
               test-vectors/signing_ed25519_v1.json; Python
               signing_ed25519_cross_verify.py recomputes public keys and
               signatures from fixed seeds.
```

---

## ML-KEM Library Audit Status

```
Library:      ml-kem (RustCrypto)
Version:      0.3.2 (pinned in Cargo.lock)
Audit status: No independent audit as of 2026-06; FIPS 203 target;
              constant-time via subtle; wide deployment/community review
Risk level:   Medium — see ADR-034, ADR-012
Tracking:     docs/ops/dependency_risk_register.md
```

This field must be updated with the pinned Cargo.lock version before MVP-2 ships.

---

## X25519 Library Audit Status

```
Library:      x25519-dalek (dalek-cryptography)
Version:      2.x (pinned in Cargo.lock)
Audit status: No independent audit as of 2026-06; widely deployed;
              constant-time scalar multiplication via curve25519-dalek;
              low-order point rejection NOT enforced by this crate
              (hybrid security relies on ML-KEM component in that case).
Risk level:   Low-Medium — established library, no known CVEs
Tracking:     docs/ops/dependency_risk_register.md
```

---

## Ed25519 Library Audit Status

```
Library:      ed25519-dalek (dalek-cryptography)
Version:      2.2.0 (pinned in Cargo.lock)
Audit status: Widely deployed Rust Ed25519 implementation; ADR-020
              dependency addition approved for PQC-3.
Risk level:   Low-Medium — established classical signature primitive; no HNDL
              urgency for authenticity per ADR-028
Tracking:     docs/ops/dependency_risk_register.md
```

---

## Preconditions

```
[P-01] MlKemPublicKey must be the full 1184-byte ML-KEM-768 public key.

[P-02] transcript_hash passed to derive_transfer_key and receive_transfer_key
       must be computed over all required fields per
       specs/protocol/transfer_profile_v1.md §4.

[P-03] X25519 ephemeral key must be freshly generated per transfer.
       Reusing ephemeral keys breaks forward secrecy.

[P-04] The `message` argument to mldsa::sign() MUST be a domain-separated
       protocol transcript. Callers are responsible for including a context
       string that identifies the protocol, role, and algorithm version before
       the payload bytes (e.g. "meissnerseal.device.enrollment.v1\x00" ||
       payload). Passing raw payload bytes without domain context creates
       cross-protocol replay risk. mldsa::sign() does not add its own prefix;
       domain separation is the caller's responsibility so XFER-1 and
       DEVICE-1 can each control their own transcript format.
       See F-39 in docs/security/finding_register.yaml.
```

---

## Invariants

```
[I-01] This crate never logs or exposes key material.
[I-02] This crate never falls back to classical-only mode silently.
[I-03] Hybrid derivation parameters match the profile ID in the envelope.
```
