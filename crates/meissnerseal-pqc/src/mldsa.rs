// SPDX-License-Identifier: Apache-2.0
//! Algorithm-tagged device signing keys (ADR-028).
//!
//! MVP-2 implements only `Ed25519V1` as the active signing backend. The
//! `Ed25519MlDsa87HybridV1` identifier is a fail-closed agility slot: it is
//! carried in types and parsing so protocols can authenticate algorithm
//! identifiers now, but all sign/verify operations for that slot return
//! `Unimplemented` until a future ML-DSA backend is approved and audited.

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

    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 2] {
        self.to_u16().to_le_bytes()
    }

    pub const fn from_le_bytes(bytes: [u8; 2]) -> Result<Self> {
        Self::from_u16(u16::from_le_bytes(bytes))
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

    /// Audited escape hatch for cross-crate serialization (F-53).
    ///
    /// The bytes must not outlive the closure. Callers that need to persist a
    /// copy must wrap in `Zeroizing<Vec<u8>>`. All call sites are in
    /// meissnerseal-core and tracked in the finding register.
    pub fn with_secret_bytes<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(&self.bytes)
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

/// Generate a fresh Ed25519V1 signing keypair.
///
/// # Contract
///
/// ## Preconditions
/// - Randomness must come from the operating-system CSPRNG path exposed by
///   `meissnerseal-crypto`.
/// - Callers cannot provide deterministic seed material in production builds.
///
/// ## Postconditions
/// - Returns a `SigningPublicKey` tagged `SigningAlgorithmId::Ed25519V1`.
/// - Returns a `SigningPrivateKey` tagged `SigningAlgorithmId::Ed25519V1`.
/// - Private key seed material is stored in `SigningPrivateKey` as
///   `Zeroizing<Vec<u8>>`.
///
/// ## Invariants
/// - Never logs, prints, or exposes raw private key bytes.
/// - Does not implement Ed25519 directly; key expansion and public-key
///   derivation go through `ed25519-dalek`.
#[must_use]
pub fn ed25519_keypair() -> (SigningPublicKey, SigningPrivateKey) {
    let seed = Zeroizing::new(meissnerseal_crypto::rng::random_key());
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    (
        SigningPublicKey::new(
            SigningAlgorithmId::Ed25519V1,
            verifying_key.to_bytes().to_vec(),
        ),
        SigningPrivateKey::new(SigningAlgorithmId::Ed25519V1, seed.to_vec()),
    )
}

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

/// Sign a payload with an explicit domain separator (F-52, CONTRACT.md [P-04]).
///
/// Prefer this over `sign` for all protocol operations. Passing `domain` and
/// `payload` separately makes domain separation structurally mandatory, preventing
/// cross-protocol replay when new callers are added. Example domains:
/// `b"meissnerseal.device.enrollment.v1\x00"`,
/// `b"meissnerseal.transfer.envelope.v1\x00"`.
pub fn sign_with_domain(
    private_key: &SigningPrivateKey,
    domain: &[u8],
    payload: &[u8],
) -> Result<Signature> {
    let mut message = Vec::with_capacity(domain.len().saturating_add(payload.len()));
    message.extend_from_slice(domain);
    message.extend_from_slice(payload);
    sign(private_key, &message)
}

/// Verify a signature produced by `sign_with_domain` for the same domain and payload.
///
/// Prefer this over `verify` for all protocol operations. CONTRACT.md [P-04].
pub fn verify_with_domain(
    public_key: &SigningPublicKey,
    domain: &[u8],
    payload: &[u8],
    signature: &Signature,
) -> Result<()> {
    let mut message = Vec::with_capacity(domain.len().saturating_add(payload.len()));
    message.extend_from_slice(domain);
    message.extend_from_slice(payload);
    verify(public_key, &message, signature)
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
    use serde::Deserialize;

    const SIGNING_ED25519_KAT: &str = include_str!("../../../test-vectors/signing_ed25519_v1.json");
    const MESSAGE: &[u8] = b"meissnerseal signing test message";
    const OTHER_MESSAGE: &[u8] = b"meissnerseal altered signing test message";

    #[derive(Deserialize)]
    struct KatFile {
        algorithm_id_u16_le: String,
        cases: Vec<KatCase>,
    }

    #[derive(Deserialize)]
    struct KatCase {
        case_id: String,
        private_key_seed: String,
        public_key: String,
        message: String,
        expected_signature: String,
    }

    fn load_kat() -> KatFile {
        serde_json::from_str(SIGNING_ED25519_KAT).expect("signing_ed25519_v1.json must be valid")
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

    #[test]
    fn sign_verify_ed25519_roundtrip() {
        let private_key = ed25519_private_key();
        let public_key = ed25519_public_key();

        let signature = sign(&private_key, MESSAGE).expect("Ed25519 signing succeeds");
        verify(&public_key, MESSAGE, &signature).expect("Ed25519 verification succeeds");
    }

    #[test]
    fn ed25519_keypair_sign_verify_roundtrip() {
        let (public_key, private_key) = ed25519_keypair();

        let signature = sign(&private_key, MESSAGE).expect("generated key signs");
        verify(&public_key, MESSAGE, &signature).expect("generated public key verifies");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let private_key = ed25519_private_key();
        let public_key = ed25519_public_key();

        let signature = sign(&private_key, MESSAGE).expect("Ed25519 signing succeeds");
        assert!(matches!(
            verify(&public_key, OTHER_MESSAGE, &signature),
            Err(SigningError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_rejects_malformed_public_key() {
        let public_key = SigningPublicKey::new(SigningAlgorithmId::Ed25519V1, vec![0u8; 5]);
        let private_key = ed25519_private_key();
        let signature = sign(&private_key, MESSAGE).expect("Ed25519 signing succeeds");
        assert!(matches!(
            verify(&public_key, MESSAGE, &signature),
            Err(SigningError::InvalidKey)
        ));
    }

    #[test]
    fn verify_rejects_malformed_signature_length() {
        let public_key = ed25519_public_key();
        let signature = Signature::new(SigningAlgorithmId::Ed25519V1, vec![0u8; 5]);
        assert!(matches!(
            verify(&public_key, MESSAGE, &signature),
            Err(SigningError::MalformedSignature)
        ));
    }

    #[test]
    fn sign_rejects_malformed_private_key_length() {
        let private_key = SigningPrivateKey::new(SigningAlgorithmId::Ed25519V1, vec![0u8; 5]);
        assert!(matches!(
            sign(&private_key, MESSAGE),
            Err(SigningError::InvalidKey)
        ));
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
    fn verify_with_domain_rejects_wrong_domain_signature() {
        let private_key = ed25519_private_key();
        let public_key = ed25519_public_key();
        let payload = b"same payload";
        let signature =
            sign_with_domain(&private_key, b"meissnerseal.domain.a\x00", payload).expect("signs");

        assert!(matches!(
            verify_with_domain(
                &public_key,
                b"meissnerseal.domain.b\x00",
                payload,
                &signature
            ),
            Err(SigningError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_with_domain_rejects_wrong_payload() {
        let (pub_key, priv_key) = ed25519_keypair();
        let domain = b"meissnerseal.test.v1\x00";
        let sig = sign_with_domain(&priv_key, domain, b"original").expect("sign");
        assert!(matches!(
            verify_with_domain(&pub_key, domain, b"altered", &sig),
            Err(SigningError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_rejects_malformed_signature_bytes() {
        let public_key = ed25519_public_key();
        let malformed = Signature::new(SigningAlgorithmId::Ed25519V1, vec![0xff; 64]);
        assert!(matches!(
            verify(&public_key, MESSAGE, &malformed),
            Err(SigningError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_rejects_cross_algorithm_signature_before_primitive_dispatch() {
        let public_key =
            SigningPublicKey::new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, vec![0x5a; 128]);
        let private_key = ed25519_private_key();
        let signature = sign(&private_key, MESSAGE).expect("Ed25519 signing succeeds");

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
    fn algorithm_id_le_bytes_ed25519_v1() {
        assert_eq!(SigningAlgorithmId::Ed25519V1.to_le_bytes(), [0x01, 0x00]);
        assert!(matches!(
            SigningAlgorithmId::from_le_bytes([0x01, 0x00]),
            Ok(SigningAlgorithmId::Ed25519V1)
        ));
    }

    #[test]
    fn algorithm_id_le_bytes_hybrid_v1() {
        assert_eq!(
            SigningAlgorithmId::Ed25519MlDsa87HybridV1.to_le_bytes(),
            [0x02, 0x00]
        );
        assert!(matches!(
            SigningAlgorithmId::from_le_bytes([0x02, 0x00]),
            Ok(SigningAlgorithmId::Ed25519MlDsa87HybridV1)
        ));
    }

    #[test]
    fn algorithm_id_from_u16_unknown_is_rejected() {
        assert!(matches!(
            SigningAlgorithmId::from_u16(0xffff),
            Err(SigningError::UnknownAlgorithm)
        ));
        assert!(matches!(
            SigningAlgorithmId::from_le_bytes([0xff, 0xff]),
            Err(SigningError::UnknownAlgorithm)
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
        private_key.with_secret_bytes(|bytes| assert_eq!(bytes.len(), 32));
    }

    #[test]
    fn ed25519_v1_kat_all_cases_match() {
        let kat = load_kat();
        assert_eq!(
            kat.algorithm_id_u16_le, "0100",
            "algorithm_id_u16_le must be Ed25519V1 little-endian encoding of 0x0001"
        );
        let expected_alg_id_le = from_hex(&kat.algorithm_id_u16_le);
        let json_case_count = serde_json::from_str::<serde_json::Value>(SIGNING_ED25519_KAT)
            .expect("signing_ed25519_v1.json must parse")
            .get("cases")
            .and_then(serde_json::Value::as_array)
            .map(std::vec::Vec::len)
            .expect("JSON must contain cases array");
        assert_eq!(
            kat.cases.len(),
            json_case_count,
            "typed KAT loader must consume every JSON case"
        );
        assert!(!kat.cases.is_empty(), "KAT must contain at least one case");

        let mut seen_ids = std::collections::HashSet::new();
        for case in &kat.cases {
            assert!(
                seen_ids.insert(case.case_id.as_str()),
                "duplicate case_id: {}",
                case.case_id
            );

            let seed = from_hex(&case.private_key_seed);
            let public_key_bytes = from_hex(&case.public_key);
            let message = from_hex(&case.message);
            let expected_sig = from_hex(&case.expected_signature);

            let seed_arr: [u8; 32] = seed
                .as_slice()
                .try_into()
                .expect("seed must be 32 bytes");
            let derived_pub = ed25519_dalek::SigningKey::from_bytes(&seed_arr)
                .verifying_key()
                .to_bytes()
                .to_vec();
            assert_eq!(
                derived_pub, public_key_bytes,
                "{}: public_key does not match seed derivation",
                case.case_id
            );

            let private_key = SigningPrivateKey::new(SigningAlgorithmId::Ed25519V1, seed);
            let public_key = SigningPublicKey::new(SigningAlgorithmId::Ed25519V1, public_key_bytes);

            let signature = sign(&private_key, &message).expect("Ed25519V1 KAT sign must succeed");

            assert_eq!(
                signature.algorithm().to_u16().to_le_bytes(),
                expected_alg_id_le.as_slice(),
                "{}: algorithm ID LE mismatch",
                case.case_id
            );
            assert_eq!(
                signature.as_bytes(),
                expected_sig.as_slice(),
                "{}: signature bytes mismatch",
                case.case_id
            );

            verify(&public_key, &message, &signature).expect("Ed25519V1 KAT verify must succeed");
        }
    }

    #[test]
    fn sign_with_domain_matches_manual_domain_prepend() {
        let private_key = ed25519_private_key();
        let public_key = ed25519_public_key();
        let domain = b"meissnerseal.test.domain.v1\x00";
        let payload = b"test payload bytes";

        let sig_via_api =
            sign_with_domain(&private_key, domain, payload).expect("sign_with_domain succeeds");

        let mut manual = Vec::new();
        manual.extend_from_slice(domain);
        manual.extend_from_slice(payload);
        let sig_manual = sign(&private_key, &manual).expect("manual sign succeeds");

        assert_eq!(sig_via_api.as_bytes(), sig_manual.as_bytes());
        verify_with_domain(&public_key, domain, payload, &sig_via_api)
            .expect("verify_with_domain accepts matching signature");
    }

    #[test]
    fn sign_with_domain_different_domains_produce_different_signatures() {
        let private_key = ed25519_private_key();
        let payload = b"same payload";

        let sig_a =
            sign_with_domain(&private_key, b"domain.a\x00", payload).expect("sign domain a");
        let sig_b =
            sign_with_domain(&private_key, b"domain.b\x00", payload).expect("sign domain b");

        assert_ne!(sig_a.as_bytes(), sig_b.as_bytes());
    }

    fn ed25519_private_key() -> SigningPrivateKey {
        let kat = load_kat();
        let case = kat.cases.first().expect("KAT must have at least one case");
        SigningPrivateKey::new(
            SigningAlgorithmId::Ed25519V1,
            from_hex(&case.private_key_seed),
        )
    }

    fn ed25519_public_key() -> SigningPublicKey {
        let kat = load_kat();
        let case = kat.cases.first().expect("KAT must have at least one case");
        SigningPublicKey::new(SigningAlgorithmId::Ed25519V1, from_hex(&case.public_key))
    }
}
