// SPDX-License-Identifier: Apache-2.0
//! Algorithm-tagged device signing keys (ADR-028).
//!
//! Keys and signatures carry an explicit `SigningAlgorithmId`, and the
//! enclosing protocol authenticates that identifier for downgrade resistance.
//!
//! MVP-2 supports both `Ed25519V1` and `Ed25519MlDsa87HybridV1`. The hybrid
//! wire encoding follows `transfer_profile_v1.md §6` exactly:
//! `ed25519_vk || mldsa87_vk` for public keys and
//! `ed25519_sig || mldsa87_sig` for signatures.
//!
//! Per ADR-028 (amendment 2026-07-23), the hybrid verifier uses a strict AND
//! combiner: both the Ed25519 and ML-DSA-87 components must verify
//! independently or the signature is rejected.

use ed25519_dalek::{Signer, VerifyingKey};
use getrandom04::SysRng as GetrandomRng;
use ml_dsa::{
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, Keypair as MlDsaKeypair, MlDsa87,
    Signature as MlDsaSignature, SigningKey as MlDsaSigningKey, Verifier as MlDsaVerifier,
    VerifyingKey as MlDsaVerifyingKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MLDSA87_PUBLIC_KEY_LEN: usize = 2592;
pub const MLDSA87_SIGNATURE_LEN: usize = 4627;
pub const MLDSA87_SEED_LEN: usize = 32;
pub const HYBRID_PUBLIC_KEY_LEN: usize = 32 + MLDSA87_PUBLIC_KEY_LEN;
pub const HYBRID_SIGNATURE_LEN: usize = 64 + MLDSA87_SIGNATURE_LEN;
pub const HYBRID_PRIVATE_KEY_LEN: usize = 32 + MLDSA87_SEED_LEN;

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
/// - The hybrid slot is explicit on the wire and is never inferred from a byte
///   layout heuristic.
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
/// - Hybrid public keys use the ADR-028 wire encoding (amendment 2026-07-23).
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

/// Expected byte lengths per algorithm, used by `try_new`.
const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;
const ED25519_SEED_LEN: usize = 32;

impl SigningPublicKey {
    pub(crate) fn new(algorithm: SigningAlgorithmId, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Construct a validated public key for the given algorithm.
    ///
    /// # Errors
    /// Returns `InvalidKey` if `bytes` do not match the expected length for
    /// `algorithm`, or if the hybrid encoding fails component decoding.
    pub fn try_new(algorithm: SigningAlgorithmId, bytes: Vec<u8>) -> Result<Self> {
        match algorithm {
            SigningAlgorithmId::Ed25519V1 => {
                if bytes.len() != ED25519_PUBLIC_KEY_LEN {
                    return Err(SigningError::InvalidKey);
                }
                Ok(Self { algorithm, bytes })
            }
            SigningAlgorithmId::Ed25519MlDsa87HybridV1 => Self::try_new_ed25519_mldsa87(bytes),
        }
    }

    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithmId {
        self.algorithm
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Construct an Ed25519+ML-DSA-87 hybrid public key from the concatenated
    /// wire encoding.
    ///
    /// # Contract
    ///
    /// ## Preconditions
    /// - `bytes` must be the exact concatenation
    ///   `ed25519_vk (32 B) || mldsa87_vk (2592 B)`.
    /// - Callers must not pass a partial component or an alternate layout.
    ///
    /// ## Postconditions
    /// - On success, returns a `SigningPublicKey` tagged
    ///   `SigningAlgorithmId::Ed25519MlDsa87HybridV1`.
    /// - On failure, returns a specific `SigningError`; the hybrid constructor
    ///   never falls back to a single-component key.
    ///
    /// ## Invariants
    /// - Hybrid verification is fail-closed: both components are mandatory.
    /// - Lengths are checked against named wire constants, never magic numbers.
    pub fn try_new_ed25519_mldsa87(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != HYBRID_PUBLIC_KEY_LEN {
            return Err(SigningError::InvalidKey);
        }
        let (ed25519_part, mldsa_part) = bytes.split_at(32);

        let ed25519_bytes: &[u8; 32] = ed25519_part
            .try_into()
            .map_err(|_| SigningError::InvalidKey)?;
        VerifyingKey::from_bytes(ed25519_bytes).map_err(|_| SigningError::InvalidKey)?;

        let mldsa_bytes = MlDsaEncodedVerifyingKey::<MlDsa87>::try_from(mldsa_part)
            .map_err(|_| SigningError::InvalidKey)?;
        let _ = MlDsaVerifyingKey::<MlDsa87>::decode(&mldsa_bytes);

        Ok(Self {
            algorithm: SigningAlgorithmId::Ed25519MlDsa87HybridV1,
            bytes,
        })
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
/// - Hybrid private key material uses `ed25519_seed || mldsa87_seed`.
///
/// ## Postconditions
/// - Signing with `Ed25519V1` returns an algorithm-tagged signature in Phase 2.
/// - Signing with `Ed25519MlDsa87HybridV1` emits a hybrid signature on success.
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
    pub(crate) fn new(algorithm: SigningAlgorithmId, bytes: Vec<u8>) -> Self {
        Self {
            algorithm,
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Construct a validated private key for the given algorithm.
    ///
    /// # Errors
    /// Returns `InvalidKey` if `bytes` do not match the expected seed length for
    /// `algorithm`, or if the hybrid seeds are all-zero.
    pub fn try_new(algorithm: SigningAlgorithmId, bytes: Vec<u8>) -> Result<Self> {
        match algorithm {
            SigningAlgorithmId::Ed25519V1 => {
                if bytes.len() != ED25519_SEED_LEN {
                    return Err(SigningError::InvalidKey);
                }
                Ok(Self {
                    algorithm,
                    bytes: Zeroizing::new(bytes),
                })
            }
            SigningAlgorithmId::Ed25519MlDsa87HybridV1 => Self::try_new_ed25519_mldsa87(bytes),
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

    /// Construct an Ed25519+ML-DSA-87 hybrid private key from the concatenated
    /// seed encoding.
    ///
    /// # Contract
    ///
    /// ## Preconditions
    /// - `seed_bytes` must be the exact concatenation
    ///   `ed25519_seed (32 B) || mldsa87_seed (32 B)`.
    /// - The Ed25519 seed component must not be all zero.
    /// - The ML-DSA-87 seed component must not be all zero.
    ///
    /// ## Postconditions
    /// - On success, returns a `SigningPrivateKey` tagged
    ///   `SigningAlgorithmId::Ed25519MlDsa87HybridV1`.
    /// - On failure, returns a specific `SigningError`; the hybrid constructor
    ///   never accepts a malformed or partial seed bundle.
    ///
    /// ## Invariants
    /// - Secret bytes remain wrapped in `Zeroizing<Vec<u8>>`.
    /// - Hybrid signing is fail-closed: both seed components are mandatory.
    /// - Lengths are checked against named wire constants, never magic numbers.
    pub fn try_new_ed25519_mldsa87(seed_bytes: Vec<u8>) -> Result<Self> {
        if seed_bytes.len() != HYBRID_PRIVATE_KEY_LEN {
            return Err(SigningError::InvalidKey);
        }
        let (ed25519_seed, mldsa_seed) = seed_bytes.split_at(32);
        if ed25519_seed.iter().all(|&byte| byte == 0) || mldsa_seed.iter().all(|&byte| byte == 0) {
            return Err(SigningError::InvalidKey);
        }
        Ok(Self {
            algorithm: SigningAlgorithmId::Ed25519MlDsa87HybridV1,
            bytes: Zeroizing::new(seed_bytes),
        })
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
/// - Hybrid signatures use the ADR-028 wire encoding (amendment 2026-07-23).
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
    pub(crate) fn new(algorithm: SigningAlgorithmId, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Construct a validated signature for the given algorithm.
    ///
    /// # Errors
    /// Returns `MalformedSignature` if `bytes` do not match the expected length
    /// for `algorithm`.
    pub fn try_new(algorithm: SigningAlgorithmId, bytes: Vec<u8>) -> Result<Self> {
        let expected = match algorithm {
            SigningAlgorithmId::Ed25519V1 => ED25519_SIGNATURE_LEN,
            SigningAlgorithmId::Ed25519MlDsa87HybridV1 => HYBRID_SIGNATURE_LEN,
        };
        if bytes.len() != expected {
            return Err(SigningError::MalformedSignature);
        }
        Ok(Self { algorithm, bytes })
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
    #[error("signing operation failed (e.g. RNG error or invalid context)")]
    SigningFailed,
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

/// Generate a fresh Ed25519+ML-DSA-87 hybrid signing keypair.
///
/// # Contract
///
/// ## Preconditions
/// - Randomness must come from the operating-system CSPRNG path exposed by
///   `meissnerseal-crypto`.
/// - The generated private seed must contain both the Ed25519 32-byte seed and
///   the ML-DSA-87 32-byte seed.
///
/// ## Postconditions
/// - On success, returns a public key with `HYBRID_PUBLIC_KEY_LEN` bytes and a
///   private key with `HYBRID_PRIVATE_KEY_LEN` bytes.
/// - Both returned values are tagged
///   `SigningAlgorithmId::Ed25519MlDsa87HybridV1`.
///
/// ## Invariants
/// - Hybrid generation is fail-closed: there is no single-component fallback.
/// - Secret seed material remains zeroized on drop.
pub fn generate_ed25519_mldsa87_keypair() -> Result<(SigningPublicKey, SigningPrivateKey)> {
    let ed25519_seed = Zeroizing::new(meissnerseal_crypto::rng::random_key());
    let mldsa_seed = Zeroizing::new(meissnerseal_crypto::rng::random_key());

    let ed25519_public_key = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed)
        .verifying_key()
        .to_bytes();
    let mldsa_signing_key = MlDsaSigningKey::<MlDsa87>::from_seed(&(*mldsa_seed).into());
    let mldsa_public_key = MlDsaKeypair::verifying_key(&mldsa_signing_key).encode();

    let mut public_key_bytes = Vec::with_capacity(HYBRID_PUBLIC_KEY_LEN);
    public_key_bytes.extend_from_slice(&ed25519_public_key);
    public_key_bytes.extend_from_slice(mldsa_public_key.as_ref());

    let mut private_key_bytes = Vec::with_capacity(HYBRID_PRIVATE_KEY_LEN);
    private_key_bytes.extend_from_slice(ed25519_seed.as_ref());
    private_key_bytes.extend_from_slice(mldsa_seed.as_ref());

    let public_key = SigningPublicKey::try_new_ed25519_mldsa87(public_key_bytes)?;
    let private_key = SigningPrivateKey::try_new_ed25519_mldsa87(private_key_bytes)?;
    Ok((public_key, private_key))
}

/// Produce an Ed25519+ML-DSA-87 hybrid signature over a domain-separated message.
///
/// # Contract
///
/// ## Preconditions
/// - `private_key` must hold the exact `ed25519_seed || mldsa87_seed` hybrid
///   seed encoding.
/// - `message` must be the fully domain-separated transcript bytes.
///
/// ## Postconditions
/// - On success, returns a `Signature` tagged
///   `Ed25519MlDsa87HybridV1` whose length is `HYBRID_SIGNATURE_LEN`.
/// - On failure of either component, returns `Err`; there is no
///   single-component success path.
///
/// ## Invariants
/// - The combiner is strict AND: both components must sign and both signatures
///   are encoded in fixed concatenation order.
/// - Seed copies are held in `Zeroizing` on the stack and cleared on drop.
/// - ML-DSA signing via `ml-dsa 0.1.1` uses the hedged variant (FIPS 204 §5.2
///   with random `rnd`). Signatures are not deterministic across calls even for
///   the same key and message. The KAT in `test-vectors/signing_hybrid_v1.json`
///   is therefore a verify-only KAT for the ML-DSA component: the stored bytes
///   were produced by an independent Python implementation and are verified by
///   Rust, not re-signed and compared byte-for-byte.
fn sign_ed25519_mldsa87_hybrid(
    private_key: &SigningPrivateKey,
    message: &[u8],
) -> Result<Signature> {
    private_key.with_secret_bytes(|bytes| {
        if bytes.len() != HYBRID_PRIVATE_KEY_LEN {
            return Err(SigningError::InvalidKey);
        }
        let (ed25519_part, mldsa_part) = bytes.split_at(32);

        if ed25519_part.iter().all(|&b| b == 0) || mldsa_part.iter().all(|&b| b == 0) {
            return Err(SigningError::InvalidKey);
        }

        let ed25519_seed = Zeroizing::new(
            <[u8; 32]>::try_from(ed25519_part).map_err(|_| SigningError::InvalidKey)?,
        );
        let mldsa_seed = Zeroizing::new(
            <[u8; MLDSA87_SEED_LEN]>::try_from(mldsa_part).map_err(|_| SigningError::InvalidKey)?,
        );

        let ed25519_signature = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed)
            .sign(message)
            .to_bytes();

        let mldsa_key = MlDsaSigningKey::<MlDsa87>::from_seed(&(*mldsa_seed).into());
        let mldsa_signature = mldsa_key
            .expanded_key()
            .sign_randomized(message, &[], &mut GetrandomRng)
            .map_err(|_| SigningError::SigningFailed)?;
        let mldsa_signature_bytes = mldsa_signature.encode();

        let mut signature_bytes = Vec::with_capacity(HYBRID_SIGNATURE_LEN);
        signature_bytes.extend_from_slice(&ed25519_signature);
        signature_bytes.extend_from_slice(mldsa_signature_bytes.as_ref());

        Ok(Signature::new(
            SigningAlgorithmId::Ed25519MlDsa87HybridV1,
            signature_bytes,
        ))
    })
}

/// Verify an Ed25519+ML-DSA-87 hybrid signature with the AND combiner.
///
/// # Contract
///
/// ## Preconditions
/// - `public_key` must hold the exact `ed25519_vk || mldsa87_vk` hybrid
///   public-key encoding.
/// - `signature` must hold the exact `ed25519_sig || mldsa87_sig` hybrid
///   signature encoding.
/// - `message` must be the exact transcript bytes that were signed.
///
/// ## Postconditions
/// - Returns `Ok(())` only when both the Ed25519 and ML-DSA-87 components
///   verify under the tagged hybrid algorithm.
/// - Returns `Err(VerificationFailed)` when either component is tampered or
///   fails verification.
///
/// ## Invariants
/// - The combiner is strict AND: verification must reject if either component
///   fails.
/// - There is no fallback to Ed25519-only or ML-DSA-only success.
/// - Ed25519 is verified first; ML-DSA is verified second — the classical
///   floor is always checked regardless of ML-DSA outcome.
fn verify_ed25519_mldsa87_hybrid(
    public_key: &SigningPublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    if public_key.as_bytes().len() != HYBRID_PUBLIC_KEY_LEN {
        return Err(SigningError::InvalidKey);
    }
    if signature.as_bytes().len() != HYBRID_SIGNATURE_LEN {
        return Err(SigningError::MalformedSignature);
    }
    let (ed25519_public_part, mldsa_public_part) = public_key.as_bytes().split_at(32);
    let (ed25519_signature_part, mldsa_signature_part) = signature.as_bytes().split_at(64);

    let ed25519_public_key_bytes: &[u8; 32] = ed25519_public_part
        .try_into()
        .map_err(|_| SigningError::InvalidKey)?;
    let ed25519_verifying_key =
        VerifyingKey::from_bytes(ed25519_public_key_bytes).map_err(|_| SigningError::InvalidKey)?;

    let mldsa_public_key_bytes = MlDsaEncodedVerifyingKey::<MlDsa87>::try_from(mldsa_public_part)
        .map_err(|_| SigningError::InvalidKey)?;
    let mldsa_verifying_key = MlDsaVerifyingKey::<MlDsa87>::decode(&mldsa_public_key_bytes);

    let ed25519_signature_bytes: &[u8; 64] = ed25519_signature_part
        .try_into()
        .map_err(|_| SigningError::MalformedSignature)?;
    let ed25519_signature = ed25519_dalek::Signature::from_bytes(ed25519_signature_bytes);
    let mldsa_signature = MlDsaSignature::<MlDsa87>::try_from(mldsa_signature_part)
        .map_err(|_| SigningError::MalformedSignature)?;

    ed25519_verifying_key
        .verify_strict(message, &ed25519_signature)
        .map_err(|_| SigningError::VerificationFailed)?;
    mldsa_verifying_key
        .verify(message, &mldsa_signature)
        .map_err(|_| SigningError::VerificationFailed)?;

    Ok(())
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
/// - For `Ed25519MlDsa87HybridV1`, signs and emits the exact wire format from
///   `transfer_profile_v1.md §6`.
/// - Returns `Err` on malformed key material.
///
/// ## Invariants
/// - Does not log, print, clone, or expose private key bytes.
/// - Does not implement signing primitives directly.
pub fn sign(private_key: &SigningPrivateKey, message: &[u8]) -> Result<Signature> {
    match private_key.algorithm() {
        SigningAlgorithmId::Ed25519V1 => private_key.with_secret_bytes(|bytes| {
            let seed = Zeroizing::new(bytes.try_into().map_err(|_| SigningError::InvalidKey)?);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let signature = signing_key.sign(message);
            Ok(Signature::new(
                SigningAlgorithmId::Ed25519V1,
                signature.to_bytes().to_vec(),
            ))
        }),
        SigningAlgorithmId::Ed25519MlDsa87HybridV1 => {
            sign_ed25519_mldsa87_hybrid(private_key, message)
        }
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
/// - Returns `Err(InvalidKey)` or `Err(MalformedSignature)` on malformed
///   hybrid inputs.
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
        SigningAlgorithmId::Ed25519MlDsa87HybridV1 => {
            verify_ed25519_mldsa87_hybrid(public_key, message, signature)
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn verify_hybrid_public_key_len() {
        assert_eq!(HYBRID_PUBLIC_KEY_LEN, 32 + MLDSA87_PUBLIC_KEY_LEN);
        assert_eq!(HYBRID_PUBLIC_KEY_LEN, 2624);
    }

    #[kani::proof]
    fn verify_hybrid_signature_len() {
        assert_eq!(HYBRID_SIGNATURE_LEN, 64 + MLDSA87_SIGNATURE_LEN);
        assert_eq!(HYBRID_SIGNATURE_LEN, 4691);
    }

    #[kani::proof]
    fn verify_hybrid_private_key_len() {
        assert_eq!(HYBRID_PRIVATE_KEY_LEN, 32 + MLDSA87_SEED_LEN);
        assert_eq!(HYBRID_PRIVATE_KEY_LEN, 64);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const SIGNING_ED25519_KAT: &str = include_str!("../../../test-vectors/signing_ed25519_v1.json");
    const SIGNING_HYBRID_KAT: &str = include_str!("../../../test-vectors/signing_hybrid_v1.json");
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

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
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
    fn hybrid_slot_rejects_malformed_lengths() {
        let private_key =
            SigningPrivateKey::new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, vec![0x5a; 63]);
        let public_key = SigningPublicKey::new(
            SigningAlgorithmId::Ed25519MlDsa87HybridV1,
            vec![0x5a; HYBRID_PUBLIC_KEY_LEN - 1],
        );
        let signature = Signature::new(
            SigningAlgorithmId::Ed25519MlDsa87HybridV1,
            vec![0x5a; HYBRID_SIGNATURE_LEN - 1],
        );

        assert!(matches!(
            sign(&private_key, MESSAGE),
            Err(SigningError::InvalidKey)
        ));
        assert!(matches!(
            verify(&public_key, MESSAGE, &signature),
            Err(SigningError::InvalidKey)
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

    #[derive(Deserialize)]
    struct HybridKatFile {
        profile: String,
        version: u8,
        algorithm_id_u16_le: String,
        cases: Vec<HybridKatCase>,
    }

    #[derive(Deserialize)]
    struct HybridKatCase {
        id: String,
        #[serde(default)]
        hybrid_public_key: String,
        #[serde(default)]
        wrong_hybrid_public_key: String,
        #[serde(default)]
        message: String,
        #[serde(default)]
        expected_hybrid_signature: String,
        #[serde(default)]
        tampered_hybrid_signature: String,
    }

    fn load_hybrid_kat() -> HybridKatFile {
        serde_json::from_str(SIGNING_HYBRID_KAT).expect("signing_hybrid_v1.json must be valid")
    }

    // Verify-only KAT: the stored signature (produced by an independent Python
    // implementation) must verify under the stored hybrid public key. ML-DSA signing
    // is hedged, so we do not re-sign and compare bytes — see contract block on
    // sign_ed25519_mldsa87_hybrid.
    #[test]
    fn hybrid_v1_kat_positive_case_verifies() {
        let kat = load_hybrid_kat();
        assert_eq!(kat.profile, "ED25519_MLDSA87_HYBRID_V1");
        assert_eq!(kat.version, 1);
        assert_eq!(kat.algorithm_id_u16_le, "0200");

        let positive = kat
            .cases
            .iter()
            .find(|c| c.id == "hybrid-sign-verify-00")
            .expect("hybrid-sign-verify-00 case must exist in signing_hybrid_v1.json");

        let public_key_bytes = from_hex(&positive.hybrid_public_key);
        let message = from_hex(&positive.message);
        let signature_bytes = from_hex(&positive.expected_hybrid_signature);

        assert_eq!(public_key_bytes.len(), HYBRID_PUBLIC_KEY_LEN);
        assert_eq!(signature_bytes.len(), HYBRID_SIGNATURE_LEN);

        let public_key = SigningPublicKey::try_new_ed25519_mldsa87(public_key_bytes)
            .expect("hybrid public key must parse");
        let signature = Signature::new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, signature_bytes);

        verify(&public_key, &message, &signature)
            .expect("Python-generated hybrid signature must verify under Rust AND combiner");
    }

    #[test]
    fn hybrid_v1_kat_tampered_ed25519_is_rejected() {
        let kat = load_hybrid_kat();
        let case = kat
            .cases
            .iter()
            .find(|c| c.id == "hybrid-tampered-ed25519-component")
            .expect("hybrid-tampered-ed25519-component case must exist in signing_hybrid_v1.json");

        let public_key_bytes = from_hex(&case.hybrid_public_key);
        let message = from_hex(&case.message);
        let signature_bytes = from_hex(&case.tampered_hybrid_signature);

        let public_key = SigningPublicKey::try_new_ed25519_mldsa87(public_key_bytes)
            .expect("hybrid public key must parse");
        let signature = Signature::new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, signature_bytes);

        assert!(
            matches!(
                verify(&public_key, &message, &signature),
                Err(SigningError::VerificationFailed)
            ),
            "tampered Ed25519 component must be rejected by AND combiner"
        );
    }

    #[test]
    fn hybrid_v1_kat_tampered_mldsa87_is_rejected() {
        let kat = load_hybrid_kat();
        let case = kat
            .cases
            .iter()
            .find(|c| c.id == "hybrid-tampered-mldsa87-component")
            .expect("hybrid-tampered-mldsa87-component case must exist in signing_hybrid_v1.json");

        let public_key_bytes = from_hex(&case.hybrid_public_key);
        let message = from_hex(&case.message);
        let signature_bytes = from_hex(&case.tampered_hybrid_signature);

        let public_key = SigningPublicKey::try_new_ed25519_mldsa87(public_key_bytes)
            .expect("hybrid public key must parse");
        let signature = Signature::new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, signature_bytes);

        assert!(
            matches!(
                verify(&public_key, &message, &signature),
                Err(SigningError::VerificationFailed)
            ),
            "tampered ML-DSA-87 component must be rejected by AND combiner"
        );
    }

    #[test]
    fn hybrid_v1_kat_wrong_public_key_is_rejected() {
        let kat = load_hybrid_kat();
        let case = kat
            .cases
            .iter()
            .find(|c| c.id == "hybrid-wrong-public-key")
            .expect("hybrid-wrong-public-key case must exist in signing_hybrid_v1.json");

        let wrong_public_key_bytes = from_hex(&case.wrong_hybrid_public_key);
        let message = from_hex(&case.message);
        let signature_bytes = from_hex(&case.expected_hybrid_signature);

        let wrong_public_key = SigningPublicKey::try_new_ed25519_mldsa87(wrong_public_key_bytes)
            .expect("wrong hybrid public key must still parse (correct length, valid points)");
        let signature = Signature::new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, signature_bytes);

        assert!(
            matches!(
                verify(&wrong_public_key, &message, &signature),
                Err(SigningError::VerificationFailed)
            ),
            "signature must be rejected when verified against a different hybrid public key"
        );
    }

    #[test]
    fn sign_with_domain_hybrid_rejects_wrong_domain() {
        let (public_key, private_key) =
            generate_ed25519_mldsa87_keypair().expect("hybrid key generation succeeds");
        let payload = b"device enrollment payload";
        let signature = sign_with_domain(
            &private_key,
            b"meissnerseal.device.enrollment.v1\x00",
            payload,
        )
        .expect("hybrid sign_with_domain succeeds");

        assert!(matches!(
            verify_with_domain(
                &public_key,
                b"meissnerseal.transfer.envelope.v1\x00",
                payload,
                &signature,
            ),
            Err(SigningError::VerificationFailed)
        ));
    }

    // PHASE-1-VECTOR:
    // from cryptography.hazmat.primitives.asymmetric import ed25519
    // ed_seed = bytes.fromhex("11" * 32)
    // mldsa_seed = bytes.fromhex("22" * 32)
    // hybrid_seed = ed_seed + mldsa_seed
    // # Phase 2 backend fills the ML-DSA public component; Phase 1 asserts only
    // # the final wire lengths from transfer_profile_v1.md §6.
    #[test]
    fn hybrid_keypair_has_correct_lengths() {
        let (public_key, private_key) =
            generate_ed25519_mldsa87_keypair().expect("hybrid key generation succeeds");

        assert_eq!(
            public_key.algorithm(),
            SigningAlgorithmId::Ed25519MlDsa87HybridV1
        );
        assert_eq!(public_key.as_bytes().len(), HYBRID_PUBLIC_KEY_LEN);
        assert_eq!(
            private_key.algorithm(),
            SigningAlgorithmId::Ed25519MlDsa87HybridV1
        );
        private_key.with_secret_bytes(|bytes| assert_eq!(bytes.len(), HYBRID_PRIVATE_KEY_LEN));
    }

    // PHASE-1-VECTOR:
    // from cryptography.hazmat.primitives.asymmetric import ed25519
    // msg = b"meissnerseal signing test message"
    // ed_seed = bytes.fromhex("11" * 32)
    // mldsa_seed = bytes.fromhex("22" * 32)
    // # Phase 2 will compute ed25519_sig || mldsa87_sig independently; Phase 1
    // # pins the required final wire length from transfer_profile_v1.md §6.
    #[test]
    fn hybrid_sign_produces_correct_length() {
        let private_key = SigningPrivateKey::try_new_ed25519_mldsa87(
            [vec![0x11; 32], vec![0x22; MLDSA87_SEED_LEN]].concat(),
        )
        .expect("hybrid private key parses");

        let signature = sign(&private_key, MESSAGE).expect("hybrid signing succeeds");
        assert_eq!(
            signature.algorithm(),
            SigningAlgorithmId::Ed25519MlDsa87HybridV1
        );
        assert_eq!(signature.as_bytes().len(), HYBRID_SIGNATURE_LEN);
    }

    // PHASE-1-VECTOR:
    // from cryptography.hazmat.primitives.asymmetric import ed25519
    // msg = b"meissnerseal signing test message"
    // ed_seed = bytes.fromhex("11" * 32)
    // mldsa_seed = bytes.fromhex("22" * 32)
    // # Phase 2 vector: derive pk, sign msg, verify both Ed25519 and ML-DSA-87.
    #[test]
    fn hybrid_verify_accepts_valid_signature() {
        let (public_key, private_key) =
            generate_ed25519_mldsa87_keypair().expect("hybrid key generation succeeds");
        let signature = sign(&private_key, MESSAGE).expect("hybrid signing succeeds");

        verify(&public_key, MESSAGE, &signature).expect("hybrid verification succeeds");
    }

    // PHASE-1-VECTOR:
    // sig = bytearray(expected_hybrid_sig)
    // sig[0] ^= 0x01
    // # Verification must fail because the Ed25519 component is part of the
    // # strict AND combiner.
    #[test]
    fn hybrid_verify_rejects_tampered_ed25519_component() {
        let (public_key, private_key) =
            generate_ed25519_mldsa87_keypair().expect("hybrid key generation succeeds");
        let mut signature = sign(&private_key, MESSAGE).expect("hybrid signing succeeds");
        let byte = signature
            .bytes
            .get_mut(0)
            .expect("hybrid signature has Ed25519 prefix");
        *byte ^= 0x01;

        assert!(matches!(
            verify(&public_key, MESSAGE, &signature),
            Err(SigningError::VerificationFailed)
        ));
    }

    // PHASE-1-VECTOR:
    // sig = bytearray(expected_hybrid_sig)
    // sig[64] ^= 0x01
    // # Verification must fail because the ML-DSA-87 component is part of the
    // # strict AND combiner.
    #[test]
    fn hybrid_verify_rejects_tampered_mldsa_component() {
        let (public_key, private_key) =
            generate_ed25519_mldsa87_keypair().expect("hybrid key generation succeeds");
        let mut signature = sign(&private_key, MESSAGE).expect("hybrid signing succeeds");
        let byte = signature
            .bytes
            .get_mut(64)
            .expect("hybrid signature has ML-DSA suffix");
        *byte ^= 0x01;

        assert!(matches!(
            verify(&public_key, MESSAGE, &signature),
            Err(SigningError::VerificationFailed)
        ));
    }

    // PHASE-1-VECTOR:
    // ed_seed = bytes(32)
    // mldsa_seed = bytes.fromhex("22" * 32)
    // hybrid_seed = ed_seed + mldsa_seed
    // assert hybrid_seed[:32] == bytes(32)
    #[test]
    fn try_new_ed25519_mldsa87_rejects_all_zero_ed_seed() {
        let hybrid_seed = [vec![0x00; 32], vec![0x22; MLDSA87_SEED_LEN]].concat();

        assert!(matches!(
            SigningPrivateKey::try_new_ed25519_mldsa87(hybrid_seed),
            Err(SigningError::InvalidKey)
        ));
    }

    // PHASE-1-VECTOR:
    // ed_seed = bytes.fromhex("11" * 32)
    // mldsa_seed = bytes(32)
    // hybrid_seed = ed_seed + mldsa_seed
    // assert hybrid_seed[32:] == bytes(32)
    #[test]
    fn try_new_ed25519_mldsa87_rejects_all_zero_mldsa_seed() {
        let hybrid_seed = [vec![0x11; 32], vec![0x00; MLDSA87_SEED_LEN]].concat();

        assert!(matches!(
            SigningPrivateKey::try_new_ed25519_mldsa87(hybrid_seed),
            Err(SigningError::InvalidKey)
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

            let seed_arr: [u8; 32] = seed.as_slice().try_into().expect("seed must be 32 bytes");
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

    #[test]
    fn sign_hybrid_is_non_deterministic_across_calls() {
        let (_, private_key) =
            generate_ed25519_mldsa87_keypair().expect("hybrid key generation succeeds");
        let msg = b"same message, same key, different ML-DSA rnd";
        let sig_a = sign(&private_key, msg).expect("first sign succeeds");
        let sig_b = sign(&private_key, msg).expect("second sign succeeds");
        assert_ne!(
            sig_a.as_bytes(),
            sig_b.as_bytes(),
            "hedged ML-DSA signing must produce different signatures across calls"
        );
    }

    #[test]
    fn sign_hybrid_rejects_all_zero_ed25519_seed() {
        let seed = [[0u8; 32], [0x42u8; 32]].concat();
        let key = SigningPrivateKey::new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, seed);
        assert!(matches!(sign(&key, b"test"), Err(SigningError::InvalidKey)));
    }

    #[test]
    fn sign_hybrid_rejects_all_zero_mldsa_seed() {
        let seed = [[0x42u8; 32], [0u8; 32]].concat();
        let key = SigningPrivateKey::new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, seed);
        assert!(matches!(sign(&key, b"test"), Err(SigningError::InvalidKey)));
    }

    #[test]
    fn try_new_public_key_rejects_wrong_length_ed25519() {
        assert!(matches!(
            SigningPublicKey::try_new(SigningAlgorithmId::Ed25519V1, vec![0u8; 31]),
            Err(SigningError::InvalidKey)
        ));
        assert!(matches!(
            SigningPublicKey::try_new(SigningAlgorithmId::Ed25519V1, vec![0u8; 33]),
            Err(SigningError::InvalidKey)
        ));
    }

    #[test]
    fn try_new_public_key_rejects_wrong_length_hybrid() {
        assert!(matches!(
            SigningPublicKey::try_new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, vec![0u8; 100]),
            Err(SigningError::InvalidKey)
        ));
    }

    #[test]
    fn try_new_private_key_rejects_wrong_length_ed25519() {
        assert!(matches!(
            SigningPrivateKey::try_new(SigningAlgorithmId::Ed25519V1, vec![0u8; 31]),
            Err(SigningError::InvalidKey)
        ));
        assert!(matches!(
            SigningPrivateKey::try_new(SigningAlgorithmId::Ed25519V1, vec![0u8; 33]),
            Err(SigningError::InvalidKey)
        ));
    }

    #[test]
    fn try_new_private_key_rejects_zero_seeds_at_construction() {
        let zero_ed25519 = [[0u8; 32], [0x42u8; 32]].concat();
        assert!(matches!(
            SigningPrivateKey::try_new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, zero_ed25519),
            Err(SigningError::InvalidKey)
        ));
        let zero_mldsa = [[0x42u8; 32], [0u8; 32]].concat();
        assert!(matches!(
            SigningPrivateKey::try_new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, zero_mldsa),
            Err(SigningError::InvalidKey)
        ));
    }

    #[test]
    fn try_new_signature_rejects_wrong_length() {
        assert!(matches!(
            Signature::try_new(SigningAlgorithmId::Ed25519V1, vec![0u8; 63]),
            Err(SigningError::MalformedSignature)
        ));
        assert!(matches!(
            Signature::try_new(SigningAlgorithmId::Ed25519MlDsa87HybridV1, vec![0u8; 100]),
            Err(SigningError::MalformedSignature)
        ));
    }

    // Rust→Python interoperability roundtrip (F-274).
    // Requires Python ≥3.11 and `pip install cryptography`.
    // Run with: cargo test -p meissnerseal-pqc -- --ignored hybrid_python_roundtrip
    #[test]
    #[ignore = "requires Python ≥3.11 with cryptography ≥42 (pip install cryptography)"]
    fn hybrid_python_roundtrip() {
        use std::process::Command;

        let (public_key, private_key) =
            generate_ed25519_mldsa87_keypair().expect("keypair generation succeeds");
        let message = b"meissnerseal hybrid roundtrip test message";
        let signature = sign(&private_key, message).expect("sign succeeds");

        let pub_hex = to_hex(public_key.as_bytes());
        let sig_hex = to_hex(signature.as_bytes());
        let msg_hex = to_hex(message);

        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors/signing_hybrid_cross_verify.py");

        let status = Command::new("python3")
            .arg(&script)
            .arg("--verify-fresh")
            .arg(&pub_hex)
            .arg(&sig_hex)
            .arg(&msg_hex)
            .status()
            .expect("python3 signing_hybrid_cross_verify.py must be executable");

        assert!(
            status.success(),
            "Python verifier rejected Rust-produced hedged hybrid signature"
        );
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
