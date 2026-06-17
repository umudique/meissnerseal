// SPDX-License-Identifier: Apache-2.0
//! X25519 + ML-KEM-768 hybrid transfer-key derivation (ADR-035).
//!
//! Implements the UG hash-everything combiner over RustCrypto primitives.
//! Test vectors in `test-vectors/transfer_hybrid_v1.json`, independently
//! cross-verified by `transfer_hybrid_cross_verify.py` using real X25519 and
//! a manual HKDF-SHA256 implementation.

use crate::mlkem::{self, MlKemCiphertext, MlKemPrivateKey, SharedSecret};
use hkdf::Hkdf;
use meissnerseal_crypto::types::Key;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub type X25519PublicKey = Key<32>;
pub type X25519PrivateKey = Key<32>;
pub type TransferKey = Key<32>;

#[derive(Debug, thiserror::Error)]
pub enum HybridError {
    #[error("X25519 key material invalid")]
    X25519Invalid,
    #[error("ML-KEM operation failed")]
    MlKemFailed,
    #[error("HKDF expand failed")]
    HkdfExpand,
}

impl From<mlkem::MlKemError> for HybridError {
    fn from(_: mlkem::MlKemError) -> Self {
        Self::MlKemFailed
    }
}

pub type Result<T> = core::result::Result<T, HybridError>;

/// Generate a fresh X25519 keypair for the classical half of transfer KEM.
///
/// # Contract
///
/// ## Preconditions
/// - The Phase 2 implementation must use `x25519-dalek` with its OS-CSPRNG
///   key-generation path.
/// - Callers cannot provide deterministic seed material in production builds.
///
/// ## Postconditions
/// - Returns a 32-byte X25519 private key and its matching 32-byte public key.
/// - The private key is freshly generated for the transfer context and is not
///   reused across envelopes.
///
/// ## Invariants
/// - Private key bytes are held only in `Key<32>`, which zeroizes on drop and
///   has redacted `Debug` output.
/// - This function never logs, prints, or writes key material.
#[must_use]
pub fn x25519_keypair() -> (X25519PrivateKey, X25519PublicKey) {
    let private_bytes = Zeroizing::new(meissnerseal_crypto::rng::random_key());
    let secret = StaticSecret::from(*private_bytes);
    let public = PublicKey::from(&secret);

    (
        X25519PrivateKey::from_bytes(secret.to_bytes()),
        X25519PublicKey::from_bytes(public.to_bytes()),
    )
}

/// Derive the sender-side transfer key with the ADR-035 UG combiner.
///
/// # Contract
///
/// ## Preconditions
/// - `sender_ephemeral_private` must be the private half matching
///   `sender_ephemeral_public`.
/// - `recipient_classical_public` must be the recipient's authenticated X25519
///   static public key.
/// - `pqc_ciphertext` and `pqc_shared_secret` must come from ML-KEM-768
///   encapsulation performed by the envelope layer before transcript
///   construction.
/// - `transcript_hash` must be SHA-256 over the v1 transfer transcript and is
///   used as the HKDF-SHA256 salt.
///
/// ## Postconditions
/// - On success, returns the 32-byte transfer payload key produced by
///   HKDF-SHA256-Extract/Expand with info
///   `b"meissnerseal-transfer-v1"`.
/// - The IKM order is fixed exactly as ADR-035 specifies:
///   `ss_ML_KEM || ss_X25519 || ct_X25519 || pk_X25519 || ct_ML_KEM`.
/// - Returns `Err` if X25519 key material cannot be used or HKDF expansion
///   fails; no classical-only fallback is produced.
///
/// ## Invariants
/// - `pk_ML_KEM` is not accepted here; it is bound by the authenticated
///   DeviceIdentity and envelope transcript.
/// - All secret intermediates are zeroized after use in the Phase 2
///   implementation.
/// - This function never logs, prints, or writes key material.
pub fn derive_transfer_key(
    sender_ephemeral_private: &X25519PrivateKey,
    sender_ephemeral_public: &X25519PublicKey,
    recipient_classical_public: &X25519PublicKey,
    pqc_ciphertext: &MlKemCiphertext,
    pqc_shared_secret: &SharedSecret,
    transcript_hash: &[u8; 32],
) -> Result<TransferKey> {
    let ss_x25519 = x25519_shared_secret(sender_ephemeral_private, recipient_classical_public);
    derive_transfer_key_from_shared_parts(
        pqc_shared_secret,
        &ss_x25519,
        sender_ephemeral_public,
        recipient_classical_public,
        pqc_ciphertext,
        transcript_hash,
    )
}

/// Derive the receiver-side transfer key with X25519 and ML-KEM decapsulation.
///
/// # Contract
///
/// ## Preconditions
/// - `recipient_classical_private` must match `recipient_classical_public`.
/// - `sender_ephemeral_public` must be the sender's X25519 ephemeral public
///   key carried by the transfer envelope.
/// - `pqc_ciphertext` must be the ML-KEM-768 ciphertext carried by the same
///   envelope.
/// - `pqc_private_key` must be the recipient's ML-KEM-768 private key.
/// - `transcript_hash` must be SHA-256 over the v1 transfer transcript and is
///   used as the HKDF-SHA256 salt.
///
/// ## Postconditions
/// - On valid inputs, returns the same 32-byte transfer key as
///   `derive_transfer_key`.
/// - Same-length tampered ML-KEM ciphertext follows FIPS 203 implicit
///   rejection through `mlkem::decapsulate`: the receiver may return `Ok` with
///   a different transfer key, and later AEAD authentication fails.
/// - Missing or structurally invalid PQC material returns `Err`; no
///   classical-only fallback is produced.
///
/// ## Invariants
/// - The combiner IKM order is the ADR-035 order:
///   `ss_ML_KEM || ss_X25519 || ct_X25519 || pk_X25519 || ct_ML_KEM`.
/// - All secret intermediates are zeroized after use in the Phase 2
///   implementation.
/// - This function never logs, prints, or writes key material.
pub fn receive_transfer_key(
    recipient_classical_private: &X25519PrivateKey,
    recipient_classical_public: &X25519PublicKey,
    sender_ephemeral_public: &X25519PublicKey,
    pqc_ciphertext: &MlKemCiphertext,
    pqc_private_key: &MlKemPrivateKey,
    transcript_hash: &[u8; 32],
) -> Result<TransferKey> {
    let ss_x25519 = x25519_shared_secret(recipient_classical_private, sender_ephemeral_public);
    let pqc_shared_secret = mlkem::decapsulate(pqc_private_key, pqc_ciphertext)?;

    derive_transfer_key_from_shared_parts(
        &pqc_shared_secret,
        &ss_x25519,
        sender_ephemeral_public,
        recipient_classical_public,
        pqc_ciphertext,
        transcript_hash,
    )
}

fn x25519_shared_secret(
    private_key: &X25519PrivateKey,
    peer_public_key: &X25519PublicKey,
) -> Zeroizing<[u8; 32]> {
    let private_bytes = Zeroizing::new(*private_key.as_bytes());
    let secret = StaticSecret::from(*private_bytes);
    let peer_public = PublicKey::from(*peer_public_key.as_bytes());
    Zeroizing::new(secret.diffie_hellman(&peer_public).to_bytes())
}

fn derive_transfer_key_from_shared_parts(
    pqc_shared_secret: &SharedSecret,
    ss_x25519: &[u8; 32],
    sender_ephemeral_public: &X25519PublicKey,
    recipient_classical_public: &X25519PublicKey,
    pqc_ciphertext: &MlKemCiphertext,
    transcript_hash: &[u8; 32],
) -> Result<TransferKey> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(1216_usize));
    ikm.extend_from_slice(pqc_shared_secret.as_slice());
    ikm.extend_from_slice(ss_x25519);
    ikm.extend_from_slice(sender_ephemeral_public.as_slice());
    ikm.extend_from_slice(recipient_classical_public.as_slice());
    ikm.extend_from_slice(pqc_ciphertext.as_slice());

    let hk = Hkdf::<Sha256>::new(Some(transcript_hash), ikm.as_slice());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"meissnerseal-transfer-v1", okm.as_mut())
        .map_err(|_| HybridError::HkdfExpand)?;

    let transfer_key = TransferKey::from_bytes(*okm);
    okm.zeroize();
    Ok(transfer_key)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const TRANSFER_HYBRID_KAT: &str = include_str!("../../../test-vectors/transfer_hybrid_v1.json");

    fn from_hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|pair| {
                let hex = std::str::from_utf8(pair).expect("valid utf8");
                u8::from_str_radix(hex, 16).expect("valid hex")
            })
            .collect()
    }

    fn parse_kat_field<'a>(json: &'a str, field: &str, case_id: &str) -> &'a str {
        let marker = format!("\"case_id\": \"{case_id}\"");
        let after_case = json.split_once(&marker).expect("case id not found").1;
        let key = format!("\"{field}\": \"");
        after_case
            .split_once(&key)
            .expect("field not found")
            .1
            .split_once('"')
            .expect("closing quote")
            .0
    }

    fn fixture() -> (
        X25519PrivateKey,
        X25519PublicKey,
        X25519PrivateKey,
        X25519PublicKey,
        MlKemPrivateKey,
        MlKemCiphertext,
        SharedSecret,
    ) {
        let (sender_private, sender_public) = x25519_keypair();
        let (recipient_private, recipient_public) = x25519_keypair();
        let (pqc_public, pqc_private) = mlkem::keypair().expect("ML-KEM keypair succeeds");
        let (pqc_ciphertext, pqc_shared_secret) =
            mlkem::encapsulate(&pqc_public).expect("ML-KEM encapsulate succeeds");

        (
            sender_private,
            sender_public,
            recipient_private,
            recipient_public,
            pqc_private,
            pqc_ciphertext,
            pqc_shared_secret,
        )
    }

    #[test]
    fn round_trip_derive_receive() {
        let (
            sender_private,
            sender_public,
            recipient_private,
            recipient_public,
            pqc_private,
            pqc_ciphertext,
            pqc_shared_secret,
        ) = fixture();
        let transcript_hash = [0x42u8; 32];

        let sender_key = derive_transfer_key(
            &sender_private,
            &sender_public,
            &recipient_public,
            &pqc_ciphertext,
            &pqc_shared_secret,
            &transcript_hash,
        )
        .expect("Phase 2 sender derivation succeeds");
        let receiver_key = receive_transfer_key(
            &recipient_private,
            &recipient_public,
            &sender_public,
            &pqc_ciphertext,
            &pqc_private,
            &transcript_hash,
        )
        .expect("Phase 2 receiver derivation succeeds");

        assert!(bool::from(sender_key.ct_eq(&receiver_key)));
    }

    #[test]
    fn different_transcript_gives_different_key() {
        let (
            sender_private,
            sender_public,
            _recipient_private,
            recipient_public,
            _pqc_private,
            pqc_ciphertext,
            pqc_shared_secret,
        ) = fixture();

        let first_key = derive_transfer_key(
            &sender_private,
            &sender_public,
            &recipient_public,
            &pqc_ciphertext,
            &pqc_shared_secret,
            &[0u8; 32],
        )
        .expect("Phase 2 first transcript derivation succeeds");
        let second_key = derive_transfer_key(
            &sender_private,
            &sender_public,
            &recipient_public,
            &pqc_ciphertext,
            &pqc_shared_secret,
            &[1u8; 32],
        )
        .expect("Phase 2 second transcript derivation succeeds");

        assert!(bool::from(!first_key.ct_eq(&second_key)));
    }

    #[test]
    fn tampered_pqc_ciphertext_gives_different_key() {
        let (
            sender_private,
            sender_public,
            recipient_private,
            recipient_public,
            pqc_private,
            pqc_ciphertext,
            pqc_shared_secret,
        ) = fixture();
        let transcript_hash = [0xA5u8; 32];
        let sender_key = derive_transfer_key(
            &sender_private,
            &sender_public,
            &recipient_public,
            &pqc_ciphertext,
            &pqc_shared_secret,
            &transcript_hash,
        )
        .expect("Phase 2 sender derivation succeeds");

        let mut tampered_bytes = *pqc_ciphertext.as_bytes();
        if let Some(first) = tampered_bytes.first_mut() {
            *first ^= 0x80;
        }
        let tampered_ciphertext = MlKemCiphertext::from_bytes(tampered_bytes);

        let receiver_key = receive_transfer_key(
            &recipient_private,
            &recipient_public,
            &sender_public,
            &tampered_ciphertext,
            &pqc_private,
            &transcript_hash,
        )
        .expect("ML-KEM implicit rejection still returns a receiver key");

        assert!(bool::from(!sender_key.ct_eq(&receiver_key)));
    }

    #[test]
    fn transfer_hybrid_v1_vectors() {
        for case_id in ["ug-combiner-transcript-00", "ug-combiner-transcript-01"] {
            let sender_private: [u8; 32] = from_hex(parse_kat_field(
                TRANSFER_HYBRID_KAT,
                "sender_ephemeral_private_key",
                case_id,
            ))
            .try_into()
            .expect("sender private key is 32 bytes");
            let sender_public: [u8; 32] = from_hex(parse_kat_field(
                TRANSFER_HYBRID_KAT,
                "sender_ephemeral_public_key",
                case_id,
            ))
            .try_into()
            .expect("sender public key is 32 bytes");
            let recipient_public: [u8; 32] = from_hex(parse_kat_field(
                TRANSFER_HYBRID_KAT,
                "recipient_classical_public_key",
                case_id,
            ))
            .try_into()
            .expect("recipient public key is 32 bytes");
            let pqc_shared_secret: [u8; 32] = from_hex(parse_kat_field(
                TRANSFER_HYBRID_KAT,
                "pqc_shared_secret",
                case_id,
            ))
            .try_into()
            .expect("PQC shared secret is 32 bytes");
            let pqc_ciphertext: [u8; 1088] = from_hex(parse_kat_field(
                TRANSFER_HYBRID_KAT,
                "pqc_ciphertext",
                case_id,
            ))
            .try_into()
            .expect("PQC ciphertext is 1088 bytes");
            let transcript_hash: [u8; 32] = from_hex(parse_kat_field(
                TRANSFER_HYBRID_KAT,
                "transcript_hash",
                case_id,
            ))
            .try_into()
            .expect("transcript hash is 32 bytes");
            let expected_transfer_key: [u8; 32] = from_hex(parse_kat_field(
                TRANSFER_HYBRID_KAT,
                "expected_transfer_key",
                case_id,
            ))
            .try_into()
            .expect("expected transfer key is 32 bytes");

            let transfer_key = derive_transfer_key(
                &X25519PrivateKey::from_bytes(sender_private),
                &X25519PublicKey::from_bytes(sender_public),
                &X25519PublicKey::from_bytes(recipient_public),
                &MlKemCiphertext::from_bytes(pqc_ciphertext),
                &SharedSecret::from_bytes(pqc_shared_secret),
                &transcript_hash,
            )
            .expect("transfer hybrid vector derives");

            let expected_transfer_key = TransferKey::from_bytes(expected_transfer_key);
            assert!(
                bool::from(transfer_key.ct_eq(&expected_transfer_key)),
                "case {case_id}: transfer key mismatch"
            );
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn hybrid_key_type_lengths() {
        kani::assert(X25519PrivateKey::LEN == 32, "X25519 private key length");
        kani::assert(X25519PublicKey::LEN == 32, "X25519 public key length");
        kani::assert(TransferKey::LEN == 32, "transfer key length");
    }

    #[kani::proof]
    fn transfer_key_ct_eq_is_total_for_fixed_length_inputs() {
        let a = TransferKey::from_bytes(kani::any::<[u8; 32]>());
        let b = TransferKey::from_bytes(kani::any::<[u8; 32]>());
        let _ = a.ct_eq(&b);
    }
}
