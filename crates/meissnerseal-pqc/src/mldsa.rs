// SPDX-License-Identifier: Apache-2.0
//! Algorithm-tagged device signing keys (ADR-028).

use ed25519_dalek::{Signer, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Wire-encodable signing algorithm identifier.
///
/// # Contract
///
/// ## Preconditions
/// - Values are encoded as little-endian `u16` on the wire.
/// - Unknown values must be rejected by parsers before signature verification.
///
/// ## Postconditions
/// - `Ed25519V1` maps to `0x0001`.
/// - `Ed25519MlDsa87HybridV1` maps to `0x0002`.
///
/// ## Invariants
/// - Algorithm identifiers are explicit and are never inferred from key length.
/// - The hybrid slot is registered but not implemented until a PQ signing audit
///   clears the ML-DSA backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum SigningAlgorithmId {
    Ed25519V1 = 0x0001,
    Ed25519MlDsa87HybridV1 = 0x0002,
}

impl SigningAlgorithmId {
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::Ed25519V1 => 0x0001,
            Self::Ed25519MlDsa87HybridV1 => 0x0002,
        }
    }

    pub const fn from_u16(value: u16) -> Result<Self> {
        match value {
            0x0001 => Ok(Self::Ed25519V1),
            0x0002 => Ok(Self::Ed25519MlDsa87HybridV1),
            _ => Err(SigningError::UnknownAlgorithm),
        }
    }
}

/// Algorithm-tagged signing public key bytes.
///
/// # Contract
///
/// ## Preconditions
/// - `algorithm` identifies the exact verification algorithm for `bytes`.
/// - Ed25519 public keys must be 32 bytes.
/// - Hybrid public keys must use the future ADR-028 concatenated encoding.
///
/// ## Postconditions
/// - The algorithm tag travels with the public key.
/// - Verification rejects a mismatch between this tag and the signature tag.
///
/// ## Invariants
/// - Public key bytes are not secret, but they are never used without their
///   algorithm tag.
#[derive(Clone, Debug)]
pub struct SigningPublicKey {
    algorithm: SigningAlgorithmId,
    bytes: Vec<u8>,
}

impl SigningPublicKey {
    #[must_use]
    pub fn new(algorithm: SigningAlgorithmId, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithmId {
        self.algorithm
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Algorithm-tagged signing private key bytes.
///
/// # Contract
///
/// ## Preconditions
/// - `algorithm` identifies the exact signing algorithm for `bytes`.
/// - Ed25519 private key material must use the Phase 2 ed25519-dalek signing
///   key encoding.
/// - Hybrid private key material is reserved and must not be accepted for live
///   signing until a PQ signing audit clears the backend.
///
/// ## Postconditions
/// - Signing with `Ed25519V1` returns an algorithm-tagged signature in Phase 2.
/// - Signing with `Ed25519MlDsa87HybridV1` returns `Err(Unimplemented)` until
///   the future PQC-4 implementation.
///
/// ## Invariants
/// - Secret bytes are held in `Zeroizing<Vec<u8>>`.
/// - `Debug` is redacted.
/// - This type does not implement `Clone`.
/// - Key bytes are zeroized on drop.
pub struct SigningPrivateKey {
    algorithm: SigningAlgorithmId,
    bytes: Zeroizing<Vec<u8>>,
}

impl SigningPrivateKey {
    #[must_use]
    pub fn new(algorithm: SigningAlgorithmId, bytes: Vec<u8>) -> Self {
        Self {
            algorithm,
            bytes: Zeroizing::new(bytes),
        }
    }

    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithmId {
        self.algorithm
    }
}

impl core::fmt::Debug for SigningPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningPrivateKey([REDACTED])")
    }
}

impl Zeroize for SigningPrivateKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for SigningPrivateKey {}

/// Algorithm-tagged signature bytes.
///
/// # Contract
///
/// ## Preconditions
/// - `algorithm` identifies the algorithm that produced `bytes`.
/// - Ed25519 signatures must be 64 bytes.
/// - Hybrid signatures must use the future ADR-028 concatenated encoding.
///
/// ## Postconditions
/// - The signature carries its algorithm ID so verification can reject
///   mismatches without trusting caller-side context.
///
/// ## Invariants
/// - Signature bytes are public authentication data, but their algorithm tag is
///   mandatory and must be authenticated by the enclosing protocol.
#[derive(Clone, Debug)]
pub struct Signature {
    algorithm: SigningAlgorithmId,
    bytes: Vec<u8>,
}

impl Signature {
    #[must_use]
    pub fn new(algorithm: SigningAlgorithmId, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithmId {
        self.algorithm
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("unknown signing algorithm")]
    UnknownAlgorithm,
    #[error("signing algorithm is not implemented")]
    Unimplemented,
    #[error("signing key or signature algorithm mismatch")]
    AlgorithmMismatch,
    #[error("invalid or malformed key material")]
    InvalidKey,
    #[error("signature bytes are malformed or wrong length")]
    MalformedSignature,
    #[error("signature verification failed")]
    VerificationFailed,
}

pub type Result<T> = core::result::Result<T, SigningError>;

/// Sign a message with an algorithm-tagged signing private key.
///
/// # Contract
///
/// ## Preconditions
/// - `private_key.algorithm()` determines the signing algorithm.
/// - `message` MUST be a domain-separated protocol transcript. Callers are
///   responsible for prepending a context string that identifies the protocol,
///   role, and algorithm version (e.g. `b"meissnerseal.device.enrollment.v1\x00"
///   || payload`). Passing raw payload bytes without domain context creates
///   cross-protocol replay risk. See CONTRACT.md [P-04] and F-39.
///
/// ## Postconditions
/// - For `Ed25519V1`, Phase 2 signs with ed25519-dalek and returns a
///   `Signature` tagged `Ed25519V1`.
/// - For `Ed25519MlDsa87HybridV1`, returns `Err(Unimplemented)` until PQC-4.
/// - Returns `Err` on malformed key material.
///
/// ## Invariants
/// - Does not log, print, clone, or expose private key bytes.
/// - Does not implement signing primitives directly.
pub fn sign(private_key: &SigningPrivateKey, message: &[u8]) -> Result<Signature> {
    match private_key.algorithm() {
        SigningAlgorithmId::Ed25519V1 => {
            let seed = Zeroizing::new(
                private_key
                    .bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| SigningError::InvalidKey)?,
            );
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let signature = signing_key.sign(message);
            Ok(Signature::new(
                SigningAlgorithmId::Ed25519V1,
                signature.to_bytes().to_vec(),
            ))
        }
        SigningAlgorithmId::Ed25519MlDsa87HybridV1 => Err(SigningError::Unimplemented),
    }
}

/// Verify an algorithm-tagged signature against an algorithm-tagged public key.
///
/// # Contract
///
/// ## Preconditions
/// - `public_key.algorithm()` must match `signature.algorithm()`.
/// - `message` is the exact protocol transcript bytes that were signed.
///
/// ## Postconditions
/// - Returns `Ok(())` only when the signature verifies under the tagged
///   algorithm and matching public key.
/// - Returns `Err(AlgorithmMismatch)` when key and signature tags differ.
/// - Returns `Err(Unimplemented)` for the hybrid slot until PQC-4.
/// - Returns `Err(MalformedSignature)` when signature bytes are wrong length.
/// - Returns `Err(VerificationFailed)` when the signature is well-formed but
///   does not verify under the given key and message.
///
/// ## Invariants
/// - Does not infer algorithms from byte lengths.
/// - Does not implement verification primitives directly.
pub fn verify(public_key: &SigningPublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    if public_key.algorithm() != signature.algorithm() {
        return Err(SigningError::AlgorithmMismatch);
    }
    match public_key.algorithm() {
        SigningAlgorithmId::Ed25519V1 => {
            let public_bytes: &[u8; 32] = public_key
                .as_bytes()
                .try_into()
                .map_err(|_| SigningError::InvalidKey)?;
            let signature_bytes: &[u8; 64] = signature
                .as_bytes()
                .try_into()
                .map_err(|_| SigningError::MalformedSignature)?;
            let verifying_key =
                VerifyingKey::from_bytes(public_bytes).map_err(|_| SigningError::InvalidKey)?;
            let ed25519_signature = ed25519_dalek::Signature::from_bytes(signature_bytes);
            verifying_key
                .verify_strict(message, &ed25519_signature)
                .map_err(|_| SigningError::VerificationFailed)
        }
        SigningAlgorithmId::Ed25519MlDsa87HybridV1 => Err(SigningError::Unimplemented),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const SIGNING_ED25519_KAT: &str = include_str!("../../../test-vectors/signing_ed25519_v1.json");
    const MESSAGE: &[u8] = b"meissnerseal signing test message";
    const OTHER_MESSAGE: &[u8] = b"meissnerseal altered signing test message";

    fn from_hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|pair| {
                let hex = std::str::from_utf8(pair).expect("valid utf8");
                u8::from_str_radix(hex, 16).expect("valid hex")
            })
            .collect()
    }

    fn parse_top_level_field<'a>(json: &'a str, field: &str) -> &'a str {
        let key = format!("\"{field}\": \"");
        json.split_once(&key)
            .expect("top-level field not found")
            .1
            .split_once('"')
            .expect("closing quote")
            .0
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

    #[test]
    fn sign_verify_ed25519_roundtrip() {
        let private_key = ed25519_private_key();
        let public_key = ed25519_public_key();

        let signature = sign(&private_key, MESSAGE).expect("Ed25519 signing succeeds");
        verify(&public_key, MESSAGE, &signature).expect("Ed25519 verification succeeds");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let private_key = ed25519_private_key();
        let public_key = ed25519_public_key();

        let signature = sign(&private_key, MESSAGE).expect("Ed25519 signing succeeds");
        assert!(verify(&public_key, OTHER_MESSAGE, &signature).is_err());
    }

    #[test]
    fn verify_rejects_algorithm_mismatch() {
        let public_key = ed25519_public_key();
        let signature = Signature::new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, vec![0u8; 64]);

        assert!(matches!(
            verify(&public_key, MESSAGE, &signature),
            Err(SigningError::AlgorithmMismatch)
        ));
    }

    #[test]
    fn hybrid_slot_sign_returns_unimplemented() {
        let private_key =
            SigningPrivateKey::new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, vec![0x5a; 128]);

        assert!(matches!(
            sign(&private_key, MESSAGE),
            Err(SigningError::Unimplemented)
        ));
    }

    #[test]
    fn hybrid_slot_verify_returns_unimplemented() {
        let public_key =
            SigningPublicKey::new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, vec![0x5a; 128]);
        let signature = Signature::new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, vec![0x5a; 64]);

        assert!(matches!(
            verify(&public_key, MESSAGE, &signature),
            Err(SigningError::Unimplemented)
        ));
    }

    #[test]
    fn signing_private_key_debug_is_redacted() {
        let private_key = ed25519_private_key();
        let debug_output = format!("{private_key:?}");
        assert_eq!(debug_output, "SigningPrivateKey([REDACTED])");
        assert!(!debug_output.contains("00"));
    }

    #[test]
    fn signing_private_key_holds_expected_algorithm_and_length() {
        let private_key = ed25519_private_key();
        assert_eq!(private_key.algorithm().to_u16(), 0x0001);
        assert_eq!(private_key.bytes.len(), 32);
    }

    #[test]
    fn ed25519_v1_kat_vector_matches_expected_signature() {
        let private_key = ed25519_private_key();
        let signature = sign(&private_key, MESSAGE).expect("Ed25519 signing succeeds");
        let expected_signature = from_hex(parse_kat_field(
            SIGNING_ED25519_KAT,
            "expected_signature",
            "ed25519-sign-00",
        ));
        let expected_alg_id_le = from_hex(parse_top_level_field(
            SIGNING_ED25519_KAT,
            "algorithm_id_u16_le",
        ));

        assert_eq!(signature.algorithm().to_u16(), 0x0001);
        assert_eq!(
            signature.algorithm().to_u16().to_le_bytes(),
            expected_alg_id_le.as_slice(),
            "Ed25519V1 algorithm ID must be 0x0001 little-endian on the wire"
        );
        assert_eq!(signature.as_bytes(), expected_signature.as_slice());
    }

    fn ed25519_private_key() -> SigningPrivateKey {
        SigningPrivateKey::new(
            SigningAlgorithmId::Ed25519V1,
            from_hex(parse_kat_field(
                SIGNING_ED25519_KAT,
                "private_key_seed",
                "ed25519-sign-00",
            )),
        )
    }

    fn ed25519_public_key() -> SigningPublicKey {
        SigningPublicKey::new(
            SigningAlgorithmId::Ed25519V1,
            from_hex(parse_kat_field(
                SIGNING_ED25519_KAT,
                "public_key",
                "ed25519-sign-00",
            )),
        )
    }
}
