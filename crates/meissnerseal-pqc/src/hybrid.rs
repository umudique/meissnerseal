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

/// Derive the X25519 public key corresponding to a static private key.
///
/// Used by boundary validators (e.g. device-keypair deserializer) to verify
/// that a stored X25519 public key matches its private key material before
/// accepting the file (F-84). Callers in meissnerseal-core must not import
/// x25519-dalek directly — use this function instead.
#[must_use]
pub fn x25519_public_from_private(private: &X25519PrivateKey) -> X25519PublicKey {
    X25519PublicKey::from_bytes(
        PublicKey::from(&StaticSecret::from(*private.as_bytes())).to_bytes(),
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
    let ss_x25519 = x25519_shared_secret(sender_ephemeral_private, recipient_classical_public)?;
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
    let ss_x25519 = x25519_shared_secret(recipient_classical_private, sender_ephemeral_public)?;
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

// RFC 7748 §6.1: implementations SHOULD check for all-zero output and abort.
// A low-order peer public key (8 small-subgroup points on Curve25519) produces
// all-zero shared secret, silently removing the classical DH contribution from
// the hybrid combiner IKM and violating the hybrid security guarantee (F-51).
fn x25519_shared_secret(
    private_key: &X25519PrivateKey,
    peer_public_key: &X25519PublicKey,
) -> Result<Zeroizing<[u8; 32]>> {
    if peer_public_key.as_slice().iter().all(|&byte| byte == 0xff) {
        return Err(HybridError::X25519Invalid);
    }
    let private_bytes = Zeroizing::new(*private_key.as_bytes());
    let secret = StaticSecret::from(*private_bytes);
    let peer_public = PublicKey::from(*peer_public_key.as_bytes());
    let shared_secret = secret.diffie_hellman(&peer_public);
    if !shared_secret.was_contributory() {
        return Err(HybridError::X25519Invalid);
    }
    let shared = Zeroizing::new(shared_secret.to_bytes());
    Ok(shared)
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
    use serde::{Deserialize, Deserializer, Serialize};

    const TRANSFER_HYBRID_KAT: &str = include_str!("../../../test-vectors/transfer_hybrid_v1.json");

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct KatFile {
        #[serde(deserialize_with = "deserialize_transfer_hybrid_schema")]
        schema: String,
        #[serde(deserialize_with = "deserialize_transfer_hybrid_profile")]
        profile: String,
        #[serde(deserialize_with = "deserialize_transfer_hybrid_version")]
        version: u32,
        description: String,
        generated_by: String,
        cases: Vec<KatCase>,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct KatCase {
        case_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<KatPath>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sender_ephemeral_private_key: Option<String>,
        sender_ephemeral_public_key: String,
        recipient_classical_private_key: String,
        recipient_classical_public_key: String,
        pqc_shared_secret: String,
        pqc_ciphertext: String,
        transcript_hash: String,
        expected_transfer_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pqc_decap_key: Option<String>,
    }

    #[derive(Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
    #[serde(rename_all = "lowercase")]
    enum KatPath {
        Sender,
        Receiver,
    }

    fn deserialize_transfer_hybrid_schema<'de, D>(
        deserializer: D,
    ) -> core::result::Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value != "transfer-hybrid-v1" {
            return Err(serde::de::Error::custom(
                "schema must be transfer-hybrid-v1",
            ));
        }
        Ok(value)
    }

    fn deserialize_transfer_hybrid_profile<'de, D>(
        deserializer: D,
    ) -> core::result::Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value != "TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1" {
            return Err(serde::de::Error::custom(
                "profile must be TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1",
            ));
        }
        Ok(value)
    }

    fn deserialize_transfer_hybrid_version<'de, D>(
        deserializer: D,
    ) -> core::result::Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        if value != 1 {
            return Err(serde::de::Error::custom("version must be 1"));
        }
        Ok(value)
    }

    fn from_hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0, "hex string must have even length");
        s.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let hex = std::str::from_utf8(pair).expect("valid utf8");
                u8::from_str_radix(hex, 16).expect("valid hex")
            })
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    #[should_panic(expected = "hex string must have even length")]
    fn from_hex_rejects_odd_length_input() {
        let _ = from_hex("abc");
    }

    #[test]
    #[ignore]
    fn generate_transfer_hybrid_kat() {
        let (sender_priv_0, sender_pub_0) = x25519_keypair();
        let (recip_priv_0, recip_pub_0) = x25519_keypair();
        let (pqc_pub_0, pqc_priv_0) = mlkem::keypair().expect("ml-kem keypair 0");
        let (pqc_ct_0, pqc_ss_0) = mlkem::encapsulate(&pqc_pub_0).expect("encapsulate 0");

        let transcript_00 = [0x00u8; 32];
        let transcript_01 = [0x01u8; 32];

        let key_00 = derive_transfer_key(
            &sender_priv_0,
            &sender_pub_0,
            &recip_pub_0,
            &pqc_ct_0,
            &pqc_ss_0,
            &transcript_00,
        )
        .expect("derive 00");
        let key_01 = derive_transfer_key(
            &sender_priv_0,
            &sender_pub_0,
            &recip_pub_0,
            &pqc_ct_0,
            &pqc_ss_0,
            &transcript_01,
        )
        .expect("derive 01");

        let (sender_priv_2, sender_pub_2) = x25519_keypair();
        let (recip_priv_2, recip_pub_2) = x25519_keypair();
        let (pqc_pub_2, pqc_priv_2) = mlkem::keypair().expect("ml-kem keypair 2");
        let (pqc_ct_2, pqc_ss_2) = mlkem::encapsulate(&pqc_pub_2).expect("encapsulate 2");
        let transcript_02 = [0x22u8; 32];

        let key_distinct = derive_transfer_key(
            &sender_priv_2,
            &sender_pub_2,
            &recip_pub_2,
            &pqc_ct_2,
            &pqc_ss_2,
            &transcript_02,
        )
        .expect("derive distinct");

        let receiver_key = receive_transfer_key(
            &recip_priv_2,
            &recip_pub_2,
            &sender_pub_2,
            &pqc_ct_2,
            &pqc_priv_2,
            &transcript_02,
        )
        .expect("receiver KAT");
        assert!(
            bool::from(key_distinct.ct_eq(&receiver_key)),
            "sender and receiver must derive the same transfer key"
        );

        let kat = KatFile {
            schema: "transfer-hybrid-v1".into(),
            profile: "TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1".into(),
            version: 1,
            description: "ADR-035 UG hash-everything combiner vectors with real ML-KEM-768 keypairs. Receiver case uses actual ML-KEM decapsulation via receive_transfer_key().".into(),
            generated_by: "generate_transfer_hybrid_kat test in crates/meissnerseal-pqc/src/hybrid.rs".into(),
            cases: vec![
                KatCase {
                    case_id: "ug-combiner-transcript-00".into(),
                    path: Some(KatPath::Sender),
                    sender_ephemeral_private_key: Some(to_hex(sender_priv_0.as_bytes())),
                    sender_ephemeral_public_key: to_hex(sender_pub_0.as_bytes()),
                    recipient_classical_private_key: to_hex(recip_priv_0.as_bytes()),
                    recipient_classical_public_key: to_hex(recip_pub_0.as_bytes()),
                    pqc_shared_secret: to_hex(pqc_ss_0.as_bytes()),
                    pqc_ciphertext: to_hex(pqc_ct_0.as_bytes()),
                    transcript_hash: to_hex(&transcript_00),
                    expected_transfer_key: to_hex(key_00.as_bytes()),
                    pqc_decap_key: Some(to_hex(pqc_priv_0.as_bytes())),
                },
                KatCase {
                    case_id: "ug-combiner-transcript-01".into(),
                    path: Some(KatPath::Sender),
                    sender_ephemeral_private_key: Some(to_hex(sender_priv_0.as_bytes())),
                    sender_ephemeral_public_key: to_hex(sender_pub_0.as_bytes()),
                    recipient_classical_private_key: to_hex(recip_priv_0.as_bytes()),
                    recipient_classical_public_key: to_hex(recip_pub_0.as_bytes()),
                    pqc_shared_secret: to_hex(pqc_ss_0.as_bytes()),
                    pqc_ciphertext: to_hex(pqc_ct_0.as_bytes()),
                    transcript_hash: to_hex(&transcript_01),
                    expected_transfer_key: to_hex(key_01.as_bytes()),
                    pqc_decap_key: Some(to_hex(pqc_priv_0.as_bytes())),
                },
                KatCase {
                    case_id: "transfer-distinct-keypairs".into(),
                    path: Some(KatPath::Sender),
                    sender_ephemeral_private_key: Some(to_hex(sender_priv_2.as_bytes())),
                    sender_ephemeral_public_key: to_hex(sender_pub_2.as_bytes()),
                    recipient_classical_private_key: to_hex(recip_priv_2.as_bytes()),
                    recipient_classical_public_key: to_hex(recip_pub_2.as_bytes()),
                    pqc_shared_secret: to_hex(pqc_ss_2.as_bytes()),
                    pqc_ciphertext: to_hex(pqc_ct_2.as_bytes()),
                    transcript_hash: to_hex(&transcript_02),
                    expected_transfer_key: to_hex(key_distinct.as_bytes()),
                    pqc_decap_key: Some(to_hex(pqc_priv_2.as_bytes())),
                },
                KatCase {
                    case_id: "transfer-receiver-path".into(),
                    path: Some(KatPath::Receiver),
                    sender_ephemeral_private_key: None,
                    sender_ephemeral_public_key: to_hex(sender_pub_2.as_bytes()),
                    recipient_classical_private_key: to_hex(recip_priv_2.as_bytes()),
                    recipient_classical_public_key: to_hex(recip_pub_2.as_bytes()),
                    pqc_shared_secret: to_hex(pqc_ss_2.as_bytes()),
                    pqc_ciphertext: to_hex(pqc_ct_2.as_bytes()),
                    transcript_hash: to_hex(&transcript_02),
                    expected_transfer_key: to_hex(key_distinct.as_bytes()),
                    pqc_decap_key: Some(to_hex(pqc_priv_2.as_bytes())),
                },
            ],
        };

        println!("{}", serde_json::to_string_pretty(&kat).expect("serialize"));
    }

    fn load_kat() -> KatFile {
        serde_json::from_str(TRANSFER_HYBRID_KAT).expect("transfer_hybrid_v1.json must be valid")
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

    // F-54: coverage for F-51 zero-check — all 8 Curve25519 small-subgroup points
    // map to all-zero X25519 output. [0u8;32] (the identity u-coordinate) is the
    // canonical test vector; the others share the same property.
    #[test]
    fn x25519_shared_secret_rejects_low_order_peer_public_key() {
        let (private, _public) = x25519_keypair();
        let low_order_peer = X25519PublicKey::from_bytes([0u8; 32]);
        assert!(matches!(
            x25519_shared_secret(&private, &low_order_peer),
            Err(HybridError::X25519Invalid)
        ));
    }

    #[test]
    fn receive_transfer_key_rejects_low_order_sender_public_key() {
        let (recipient_private, recipient_public) = x25519_keypair();
        let low_order_sender = X25519PublicKey::from_bytes([0u8; 32]);
        let (pqc_public, pqc_private) = mlkem::keypair().expect("ML-KEM keypair succeeds");
        let (pqc_ciphertext, _) =
            mlkem::encapsulate(&pqc_public).expect("ML-KEM encapsulate succeeds");
        let transcript_hash = [0x42u8; 32];

        assert!(matches!(
            receive_transfer_key(
                &recipient_private,
                &recipient_public,
                &low_order_sender,
                &pqc_ciphertext,
                &pqc_private,
                &transcript_hash,
            ),
            Err(HybridError::X25519Invalid)
        ));
    }

    #[test]
    fn derive_transfer_key_rejects_low_order_recipient_public_key() {
        let (sender_private, sender_public) = x25519_keypair();
        let low_order_recipient = X25519PublicKey::from_bytes([0u8; 32]);
        let (pqc_public, _) = mlkem::keypair().expect("ML-KEM keypair succeeds");
        let (pqc_ciphertext, pqc_shared_secret) =
            mlkem::encapsulate(&pqc_public).expect("ML-KEM encapsulate succeeds");
        let transcript_hash = [0x42u8; 32];

        assert!(matches!(
            derive_transfer_key(
                &sender_private,
                &sender_public,
                &low_order_recipient,
                &pqc_ciphertext,
                &pqc_shared_secret,
                &transcript_hash,
            ),
            Err(HybridError::X25519Invalid)
        ));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "serde_json triggers memchr SSE2 alignment UB under Miri"
    )]
    fn transfer_hybrid_v1_vectors() {
        let kat = load_kat();
        assert!(
            kat.cases.len() >= 4,
            "transfer hybrid vector file must carry the expanded case set"
        );

        for case in &kat.cases {
            let sender_public: [u8; 32] = from_hex(&case.sender_ephemeral_public_key)
                .try_into()
                .expect("sender public key is 32 bytes");
            let recipient_private: [u8; 32] = from_hex(&case.recipient_classical_private_key)
                .try_into()
                .expect("recipient private key is 32 bytes");
            let recipient_public: [u8; 32] = from_hex(&case.recipient_classical_public_key)
                .try_into()
                .expect("recipient public key is 32 bytes");
            let pqc_shared_secret: [u8; 32] = from_hex(&case.pqc_shared_secret)
                .try_into()
                .expect("PQC shared secret is 32 bytes");
            let pqc_ciphertext: [u8; 1088] = from_hex(&case.pqc_ciphertext)
                .try_into()
                .expect("PQC ciphertext is 1088 bytes");
            let transcript_hash: [u8; 32] = from_hex(&case.transcript_hash)
                .try_into()
                .expect("transcript hash is 32 bytes");
            let expected_transfer_key: [u8; 32] = from_hex(&case.expected_transfer_key)
                .try_into()
                .expect("expected transfer key is 32 bytes");

            let expected_transfer_key = TransferKey::from_bytes(expected_transfer_key);
            let recipient_public = X25519PublicKey::from_bytes(recipient_public);
            let sender_public = X25519PublicKey::from_bytes(sender_public);
            let pqc_ciphertext = MlKemCiphertext::from_bytes(pqc_ciphertext);
            let pqc_shared_secret = SharedSecret::from_bytes(pqc_shared_secret);
            let recipient_private = X25519PrivateKey::from_bytes(recipient_private);

            let derived_recipient_pub = x25519_public_from_private(&recipient_private);
            assert_eq!(
                derived_recipient_pub.as_bytes(),
                recipient_public.as_bytes(),
                "{}: recipient_classical_public_key does not match private key derivation",
                case.case_id
            );

            let sender_transfer_key =
                case.sender_ephemeral_private_key
                    .as_ref()
                    .map(|sender_private_hex| {
                        let sender_private: [u8; 32] = from_hex(sender_private_hex)
                            .try_into()
                            .expect("sender private key is 32 bytes");
                        let sender_priv_key = X25519PrivateKey::from_bytes(sender_private);
                        let derived_sender_pub = x25519_public_from_private(&sender_priv_key);
                        assert_eq!(
                            derived_sender_pub.as_bytes(),
                            sender_public.as_bytes(),
                            "{}: sender_ephemeral_public_key does not match private key derivation",
                            case.case_id
                        );
                        derive_transfer_key(
                            &sender_priv_key,
                            &sender_public,
                            &recipient_public,
                            &pqc_ciphertext,
                            &pqc_shared_secret,
                            &transcript_hash,
                        )
                        .expect("sender path derives")
                    });

            if case.path == Some(KatPath::Receiver) {
                let dk_hex = case
                    .pqc_decap_key
                    .as_ref()
                    .expect("receiver case must carry pqc_decap_key");
                let dk_bytes: [u8; 2400] = from_hex(dk_hex)
                    .try_into()
                    .expect("pqc_decap_key must be 2400 bytes");
                let pqc_private = MlKemPrivateKey::from_bytes(dk_bytes);
                let receiver_transfer_key = receive_transfer_key(
                    &recipient_private,
                    &recipient_public,
                    &sender_public,
                    &pqc_ciphertext,
                    &pqc_private,
                    &transcript_hash,
                )
                .expect("receiver KAT must succeed");
                assert!(
                    bool::from(receiver_transfer_key.ct_eq(&expected_transfer_key)),
                    "receiver case {}: transfer key mismatch",
                    case.case_id
                );
                continue;
            }

            let transfer_key = sender_transfer_key.expect("sender vectors must carry sender key");

            assert!(
                bool::from(transfer_key.ct_eq(&expected_transfer_key)),
                "case {}: transfer key mismatch",
                case.case_id
            );
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "serde_json triggers memchr SSE2 alignment UB under Miri"
    )]
    fn transfer_hybrid_kat_single_input_changes_change_output() {
        let kat = load_kat();
        let case0 = kat
            .cases
            .iter()
            .find(|case| case.case_id == "ug-combiner-transcript-00")
            .expect("case 00 present");
        let case1 = kat
            .cases
            .iter()
            .find(|case| case.case_id == "ug-combiner-transcript-01")
            .expect("case 01 present");
        let case2 = kat
            .cases
            .iter()
            .find(|case| case.case_id == "transfer-distinct-keypairs")
            .expect("distinct-keypairs case present");
        let case3 = kat
            .cases
            .iter()
            .find(|case| case.case_id == "x25519-ikm-variation-only")
            .expect("x25519-only variation case present");

        let key0 = TransferKey::from_bytes(
            from_hex(&case0.expected_transfer_key)
                .try_into()
                .expect("case0 expected key length"),
        );
        let key1 = TransferKey::from_bytes(
            from_hex(&case1.expected_transfer_key)
                .try_into()
                .expect("case1 expected key length"),
        );
        let key2 = TransferKey::from_bytes(
            from_hex(&case2.expected_transfer_key)
                .try_into()
                .expect("case2 expected key length"),
        );
        let key3 = TransferKey::from_bytes(
            from_hex(&case3.expected_transfer_key)
                .try_into()
                .expect("case3 expected key length"),
        );

        assert!(bool::from(!key0.ct_eq(&key1)));
        assert!(bool::from(!key0.ct_eq(&key2)));
        assert!(bool::from(!key0.ct_eq(&key3)));
        assert!(bool::from(!key1.ct_eq(&key2)));
        assert!(bool::from(!key1.ct_eq(&key3)));
        assert!(bool::from(!key2.ct_eq(&key3)));
    }

    #[test]
    fn x25519_keypair_outputs_are_unique() {
        let (first_private, first_public) = x25519_keypair();
        let (second_private, second_public) = x25519_keypair();
        assert!(bool::from(!first_private.ct_eq(&second_private)));
        assert!(bool::from(!first_public.ct_eq(&second_public)));
        assert!(first_private.as_slice().iter().any(|byte| *byte != 0));
        assert!(second_private.as_slice().iter().any(|byte| *byte != 0));
    }

    #[test]
    fn transfer_hybrid_kat_loader_rejects_unknown_path_value() {
        let malformed = r#"{
            "schema":"transfer-hybrid-v1",
            "profile":"TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1",
            "version":1,
            "description":"invalid path test",
            "generated_by":"test",
            "cases":[{
                "case_id":"bad-path",
                "path":"sideways",
                "sender_ephemeral_private_key":"00",
                "sender_ephemeral_public_key":"00",
                "recipient_classical_private_key":"00",
                "recipient_classical_public_key":"00",
                "pqc_shared_secret":"00",
                "pqc_ciphertext":"00",
                "transcript_hash":"00",
                "expected_transfer_key":"00"
            }]
        }"#;
        assert!(
            serde_json::from_str::<KatFile>(malformed).is_err(),
            "typed KAT loader must reject unknown path values"
        );
    }

    #[test]
    fn x25519_shared_secret_rejects_adversarial_peer_public_keys() {
        let (private, _public) = x25519_keypair();
        // All 8 Curve25519 torsion points (small-subgroup order 8).
        // Source: Bernstein et al., "Curve25519: new Diffie-Hellman speed records"
        // and RFC 7748 §6 test vectors. Every point produces all-zero DH output,
        // silently removing the X25519 contribution from the hybrid IKM.
        let low_order_points = [
            "0000000000000000000000000000000000000000000000000000000000000000", // 0 (identity)
            "0100000000000000000000000000000000000000000000000000000000000000", // order 2
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", // order 4
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", // order 8
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 4 (−1 mod p)
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 8 variant
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880", // order 4 (sign bit)
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7", // order 8 (sign bit)
        ];

        for (index, peer_hex) in low_order_points.into_iter().enumerate() {
            let peer = X25519PublicKey::from_bytes(
                from_hex(peer_hex)
                    .try_into()
                    .expect("low-order point is 32 bytes"),
            );
            assert!(
                matches!(
                    x25519_shared_secret(&private, &peer),
                    Err(HybridError::X25519Invalid)
                ),
                "low-order point index {index} must be rejected"
            );
        }

        let all_ff_peer = X25519PublicKey::from_bytes([0xff; 32]);
        assert!(matches!(
            x25519_shared_secret(&private, &all_ff_peer),
            Err(HybridError::X25519Invalid)
        ));
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
