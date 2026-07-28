// SPDX-License-Identifier: Apache-2.0
//! Transfer envelope data model and XFER-1 operation contracts.

use crate::{
    keys::device::{DeviceId, DeviceIdentity, DeviceTrustState, Timestamp},
    transfer::protocol::{
        EnvelopeId, TransferError, TransferProfileId, CLASSICAL_ALG_ID_X25519, PQC_ALG_ID_MLKEM768,
        TRANSFER_PROFILE_V1_ID,
    },
    transfer::replay::SeenEnvelopeIds,
    transfer::secret_payload::SecretPayload,
};
use meissnerseal_crypto::{
    aead::{self, Ciphertext},
    rng,
    subtle::ConstantTimeEq,
    types::XChaCha20Nonce,
};
use meissnerseal_pqc::{
    hybrid::{self, X25519PrivateKey, X25519PublicKey},
    mldsa::{self, Signature, SigningAlgorithmId, SigningPrivateKey, SigningPublicKey},
    mlkem::{self, MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey},
};

pub type Nonce = [u8; 24];

/// Transfer envelope bytes that have crossed the external trust boundary and
/// been validated as ready for `open_envelope`.
pub struct UntrustedTransferEnvelope {
    envelope: TransferEnvelope,
}

impl UntrustedTransferEnvelope {
    pub fn validate_for_open(bytes: &[u8]) -> Result<UntrustedTransferEnvelope, TransferError> {
        let envelope = parse_envelope_bytes(bytes)?;
        if envelope.recipient_device_id.is_some() {
            validate_envelope(&envelope, None)?;
        } else {
            // Anonymous envelope: the transcript hash binds the recipient's public
            // key, which is only known at open time. Check expiry now; open_envelope
            // validates the full transcript when the recipient key is supplied.
            if let Some(expires_at) = envelope.expires_at {
                if expires_at <= unix_time_millis() {
                    return Err(TransferError::ExpiredEnvelope);
                }
            }
        }

        Ok(Self { envelope })
    }
}

/// Sender identity proof for transfer-envelope opening.
///
/// # Contract
///
/// ## Preconditions
/// - Must be constructed from a validated `DeviceIdentity`.
/// - Only `Verified` and `Approved` trust states are eligible.
///
/// ## Postconditions
/// - Construction returns `Err(UntrustedSender)` for every non-eligible trust
///   state and for identities missing a signing public key.
///
/// ## Invariants
/// - `open_envelope` accepts only `TrustedSender`, not a bare
///   `SigningPublicKey`.
/// - This type does not expose a public raw-byte accessor for the wrapped key.
#[derive(Clone, Debug)]
pub struct TrustedSender(SigningPublicKey);

impl TrustedSender {
    pub fn from_verified(identity: &DeviceIdentity) -> Result<Self, TransferError> {
        if !matches!(
            identity.trust_state,
            DeviceTrustState::Verified | DeviceTrustState::Approved
        ) {
            return Err(TransferError::UntrustedSender);
        }

        let signing_public_key = identity
            .signing_public_key
            .clone()
            .ok_or(TransferError::UntrustedSender)?;

        Ok(Self(signing_public_key))
    }

    pub(crate) fn signing_public_key(&self) -> &SigningPublicKey {
        &self.0
    }
}

/// Context string for XFER-1 transfer envelope signatures.
pub const TRANSFER_ENVELOPE_SIGNING_DOMAIN: &[u8] = b"meissnerseal.transfer.envelope.v1\x00";
const TRANSFER_TRANSCRIPT_DOMAIN: &[u8] = b"meissnerseal-transfer-transcript-v1";
const TRANSFER_ENVELOPE_MAGIC: &[u8; 6] = b"MSENV\x01";

/// Compile-fail contract tests for the secret-bearing transfer payload wrapper.
///
/// These doctests document the API surface kept unrepresentable at the
/// `SecretPayload` boundary.
///
/// ```compile_fail
/// use meissnerseal_core::transfer::SecretPayload;
///
/// fn clone_payload(payload: &SecretPayload) -> SecretPayload {
///     payload.clone()
/// }
/// ```
///
/// ```compile_fail
/// use meissnerseal_core::transfer::SecretPayload;
///
/// fn leak_payload(payload: &SecretPayload) -> Vec<u8> {
///     payload.to_vec()
/// }
/// ```
///
/// ```compile_fail
/// use meissnerseal_core::transfer::CreateEnvelopeParams;
/// use meissnerseal_core::keys::device::Timestamp;
/// use meissnerseal_pqc::mldsa::{SigningAlgorithmId, SigningPrivateKey};
/// use meissnerseal_crypto::types::Key;
///
/// fn build_params(expires_at: Option<Timestamp>) -> CreateEnvelopeParams {
///     CreateEnvelopeParams {
///         sender_device_id: [0x11; 16],
///         recipient_device_id: Some([0x22; 16]),
///         anonymous_recipient_public_key: None,
///         recipient_classical_public_key: Key::from_bytes([0x44; 32]),
///         recipient_pqc_public_key: Key::from_bytes([0x55; 1184]),
///         sender_signing_private_key: SigningPrivateKey::new(
///             SigningAlgorithmId::Ed25519V1,
///             vec![0x42; 32],
///         ),
///         plaintext_payload: vec![0xAA; 8],
///         expires_at,
///     }
/// }
/// ```
/// Transfer envelope for `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1`.
///
/// # Contract
///
/// ## Preconditions
/// - `transfer_profile` must be the v1 profile.
/// - `classical_ephemeral_public_key` must be the sender X25519 ephemeral
///   public key bound into the transcript.
/// - `pqc_ciphertext` must be the ML-KEM-768 ciphertext bound into the
///   transcript and combiner.
///
/// ## Postconditions
/// - Consumers must call `validate_envelope()` before key derivation or
///   decryption.
///
/// ## Invariants
/// - Algorithm identifiers and profile are downgrade-critical and must be
///   transcript-bound.
/// - `encrypted_payload` is never returned as plaintext unless AEAD
///   authentication succeeds.
#[derive(Debug)]
pub struct TransferEnvelope {
    pub version: u16,
    pub transfer_profile: TransferProfileId,
    pub envelope_id: EnvelopeId,
    pub sender_device_id: DeviceId,
    pub recipient_device_id: Option<DeviceId>,
    pub classical_ephemeral_public_key: X25519PublicKey,
    pub pqc_ciphertext: MlKemCiphertext,
    pub transcript_hash: [u8; 32],
    pub encrypted_payload: Vec<u8>,
    pub nonce: Nonce,
    pub expires_at: Option<Timestamp>,
}

/// Inputs for the v1 transcript hash.
///
/// # Contract
///
/// ## Preconditions
/// - Fields must match `transfer_profile_v1.md §4` exactly.
/// - `recipient_device_id` must be present for identified recipients; anonymous
///   mode must bind `anonymous_recipient_public_key` instead.
///
/// ## Postconditions
/// - Produces 32 bytes of SHA-256 output.
///
/// ## Invariants
/// - Every field here is downgrade- or replay-relevant and must affect the
///   transcript hash.
pub struct TranscriptParams<'a> {
    pub transfer_profile: TransferProfileId,
    pub sender_device_id: &'a DeviceId,
    pub sender_classical_ephemeral_public_key: &'a X25519PublicKey,
    pub recipient_device_id: Option<&'a DeviceId>,
    pub anonymous_recipient_public_key: Option<&'a X25519PublicKey>,
    pub pqc_ciphertext: &'a MlKemCiphertext,
    pub classical_algorithm_id: u16,
    pub pqc_algorithm_id: u16,
    pub envelope_id: &'a EnvelopeId,
    pub expires_at: Option<Timestamp>,
}

/// Inputs for creating a sealed transfer envelope.
///
/// # Contract
///
/// ## Preconditions
/// - Sender private signing material must be algorithm-tagged and used only
///   with `TRANSFER_ENVELOPE_SIGNING_DOMAIN`.
/// - Recipient public keys must come from an authenticated `DeviceIdentity` or
///   an explicitly supplied anonymous recipient binding.
/// - If `recipient_device_id` is `None`, `anonymous_recipient_public_key` must
///   be `Some(recipient_classical_public_key)`.
/// - `expires_at`, when present, must not be in the past.
///
/// ## Postconditions
/// - Returns a sealed envelope or `Err`; it never returns partial ciphertext,
///   transfer keys, or plaintext on failure.
///
/// ## Invariants
/// - Expiry is checked before key derivation.
/// - Anonymous mode fails closed when the recipient public-key transcript
///   binding is absent.
/// - `plaintext_payload` is `SecretPayload`, preventing raw-byte plaintext
///   callers at this boundary.
pub struct CreateEnvelopeParams {
    pub sender_device_id: DeviceId,
    pub recipient_device_id: Option<DeviceId>,
    pub anonymous_recipient_public_key: Option<X25519PublicKey>,
    pub recipient_classical_public_key: X25519PublicKey,
    pub recipient_pqc_public_key: MlKemPublicKey,
    pub sender_signing_private_key: SigningPrivateKey,
    pub plaintext_payload: SecretPayload,
    pub expires_at: Option<Timestamp>,
}

/// Inputs for opening a sealed transfer envelope.
///
/// # Contract
///
/// ## Preconditions
/// - Recipient private keys must match the public keys bound by the sender's
///   authenticated recipient identity.
/// - Sender trust proof must be a `TrustedSender` constructed only from
///   `Verified` or `Approved` identities.
///
/// ## Postconditions
/// - Returns plaintext only after profile, algorithm, transcript, expiry,
///   signature, key derivation, and AEAD checks succeed.
///
/// ## Invariants
/// - Expiry and transcript mismatch are rejected before decryption.
/// - Plaintext is returned as a secret-bearing payload wrapper instead of owned
///   raw bytes.
/// - A bare `SigningPublicKey` must not remain the long-term trust proof at
///   this boundary.
///
/// ```compile_fail
/// use meissnerseal_core::transfer::{OpenEnvelopeParams, TrustedSender};
/// use meissnerseal_crypto::types::Key;
/// use meissnerseal_pqc::{mldsa, mlkem::MlKemPrivateKey};
///
/// fn raw_signing_key_must_not_compile_anymore() -> OpenEnvelopeParams {
///     let (public_key, _private_key) = mldsa::ed25519_keypair();
///     OpenEnvelopeParams {
///         recipient_classical_private_key: Key::from_bytes([0x88; 32]),
///         recipient_classical_public_key: Key::from_bytes([0x44; 32]),
///         recipient_pqc_private_key: MlKemPrivateKey::from_bytes([0x99; 2400]),
///         sender_signing_public_key: public_key,
///     }
/// }
/// ```
///
pub struct OpenEnvelopeParams {
    pub recipient_classical_private_key: X25519PrivateKey,
    pub recipient_classical_public_key: X25519PublicKey,
    pub recipient_pqc_private_key: MlKemPrivateKey,
    pub sender_signing_public_key: TrustedSender,
}

/// Compute the SHA-256 transcript hash per `transfer_profile_v1.md §4`.
///
/// # Contract
///
/// ## Preconditions
/// - `params` must contain the exact profile, device IDs/public key fallback,
///   PQC ciphertext, algorithm IDs, envelope ID, and expiry to bind.
///
/// ## Postconditions
/// - Returns `SHA256(transcript_input)` as a `[u8; 32]`.
///
/// ## Invariants
/// - Any change to a bound field changes the hash with SHA-256 collision
///   resistance.
/// - Core must call a `meissnerseal-crypto` hash helper; it must not implement
///   SHA-256 directly.
#[must_use]
pub fn compute_transcript_hash(params: &TranscriptParams<'_>) -> [u8; 32] {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(TRANSFER_TRANSCRIPT_DOMAIN);
    transcript.extend_from_slice(&params.transfer_profile.to_u16().to_le_bytes());
    transcript.extend_from_slice(params.sender_device_id);
    transcript.extend_from_slice(params.sender_classical_ephemeral_public_key.as_slice());
    if let Some(recipient_device_id) = params.recipient_device_id {
        transcript.extend_from_slice(recipient_device_id);
    } else if let Some(anonymous_recipient_public_key) = params.anonymous_recipient_public_key {
        transcript.extend_from_slice(anonymous_recipient_public_key.as_slice());
    }
    transcript.extend_from_slice(
        &(u32::try_from(params.pqc_ciphertext.as_slice().len()).unwrap_or(u32::MAX)).to_le_bytes(),
    );
    transcript.extend_from_slice(params.pqc_ciphertext.as_slice());
    transcript.extend_from_slice(&params.classical_algorithm_id.to_le_bytes());
    transcript.extend_from_slice(&params.pqc_algorithm_id.to_le_bytes());
    transcript.extend_from_slice(params.envelope_id);
    let expires_i64 = params
        .expires_at
        .map(|timestamp| timestamp as i64)
        .unwrap_or(0);
    transcript.extend_from_slice(&expires_i64.to_le_bytes());

    meissnerseal_crypto::hash::sha256_bytes(&transcript)
}

/// Validate an envelope before key derivation or decryption.
///
/// # Contract
///
/// ## Preconditions
/// - Must be called before any X25519, ML-KEM, HKDF, signature verification, or
///   AEAD operation.
///
/// ## Postconditions
/// - Returns `Err(ExpiredEnvelope)` for past `expires_at` values before key
///   derivation.
/// - Returns `Err(UnknownProfile)` or `Err(AlgorithmMismatch)` for profile or
///   algorithm mismatches.
/// - Returns `Err(TranscriptMismatch)` before decryption when the stored hash
///   does not match the recomputed transcript.
///
/// ## Invariants
/// - Fail closed; no plaintext or key material is produced by validation.
pub fn validate_envelope(
    envelope: &TransferEnvelope,
    anonymous_recipient_public_key: Option<&X25519PublicKey>,
) -> Result<(), TransferError> {
    if envelope.version != 1 {
        return Err(TransferError::UnknownProfile);
    }
    if envelope.transfer_profile.to_u16() != TRANSFER_PROFILE_V1_ID {
        return Err(TransferError::UnknownProfile);
    }
    if let Some(expires) = envelope.expires_at {
        if expires <= unix_time_millis() {
            return Err(TransferError::ExpiredEnvelope);
        }
    }

    let transcript_params = TranscriptParams {
        transfer_profile: envelope.transfer_profile,
        sender_device_id: &envelope.sender_device_id,
        sender_classical_ephemeral_public_key: &envelope.classical_ephemeral_public_key,
        recipient_device_id: envelope.recipient_device_id.as_ref(),
        anonymous_recipient_public_key,
        pqc_ciphertext: &envelope.pqc_ciphertext,
        classical_algorithm_id: CLASSICAL_ALG_ID_X25519,
        pqc_algorithm_id: PQC_ALG_ID_MLKEM768,
        envelope_id: &envelope.envelope_id,
        expires_at: envelope.expires_at,
    };
    let computed = compute_transcript_hash(&transcript_params);
    if !bool::from(computed.ct_eq(&envelope.transcript_hash)) {
        return Err(TransferError::TranscriptMismatch);
    }

    Ok(())
}

/// Create a sealed transfer envelope.
///
/// # Contract
///
/// ## Preconditions
/// - `expires_at`, when present, must be in the future at call time.
/// - Transfer signing must prepend `TRANSFER_ENVELOPE_SIGNING_DOMAIN`.
/// - Anonymous mode requires `anonymous_recipient_public_key` to be present
///   and equal to the recipient classical public key bound into the KEM.
///
/// ## Postconditions
/// - Returns a sealed envelope authenticated under the v1 transcript.
/// - Returns `Err` without partial output if any validation, key derivation,
///   signing, or encryption step fails.
///
/// ## Invariants
/// - Expiry is checked before key derivation or encryption.
/// - No plaintext secret appears in error messages or logs.
/// - Returns no raw plaintext `Vec<u8>` at this boundary.
pub fn create_envelope(params: CreateEnvelopeParams) -> Result<TransferEnvelope, TransferError> {
    if let Some(expires) = params.expires_at {
        if expires <= unix_time_millis() {
            return Err(TransferError::ExpiredEnvelope);
        }
    }
    if params.recipient_device_id.is_none() && params.anonymous_recipient_public_key.is_none() {
        return Err(TransferError::MissingAnonymousRecipientPublicKey);
    }

    let envelope_id: EnvelopeId = rng::random_bytes(16)
        .try_into()
        .map_err(|_| TransferError::InvalidEnvelopeId)?;
    let (ephemeral_private, ephemeral_public) = hybrid::x25519_keypair();
    let (pqc_ciphertext, pqc_shared_secret) = mlkem::encapsulate(&params.recipient_pqc_public_key)
        .map_err(|_| TransferError::KeyDerivationFailed)?;
    let transcript_params = TranscriptParams {
        transfer_profile: TransferProfileId::v1(),
        sender_device_id: &params.sender_device_id,
        sender_classical_ephemeral_public_key: &ephemeral_public,
        recipient_device_id: params.recipient_device_id.as_ref(),
        anonymous_recipient_public_key: params.anonymous_recipient_public_key.as_ref(),
        pqc_ciphertext: &pqc_ciphertext,
        classical_algorithm_id: CLASSICAL_ALG_ID_X25519,
        pqc_algorithm_id: PQC_ALG_ID_MLKEM768,
        envelope_id: &envelope_id,
        expires_at: params.expires_at,
    };
    let transcript_hash = compute_transcript_hash(&transcript_params);
    let transfer_key = hybrid::derive_transfer_key(
        &ephemeral_private,
        &ephemeral_public,
        &params.recipient_classical_public_key,
        &pqc_ciphertext,
        &pqc_shared_secret,
        &transcript_hash,
    )
    .map_err(|_| TransferError::KeyDerivationFailed)?;

    let signature = mldsa::sign_with_domain(
        &params.sender_signing_private_key,
        TRANSFER_ENVELOPE_SIGNING_DOMAIN,
        &transcript_hash,
    )
    .map_err(|_| TransferError::SigningFailed)?;

    // transfer_profile_v1.md §2 defines no cleartext signature field on
    // TransferEnvelope. Keep the public envelope layout unchanged and carry
    // algorithm-tagged signature bytes inside the AEAD payload.
    let sealed_payload = encode_signed_payload(&signature, params.plaintext_payload)?;
    let encrypt_result = sealed_payload
        .with_secret(|payload| aead::encrypt(&transfer_key, payload, &transcript_hash));
    let (ciphertext, nonce) = encrypt_result.map_err(|_| TransferError::EncryptionFailed)?;

    Ok(TransferEnvelope {
        version: 1,
        transfer_profile: TransferProfileId::v1(),
        envelope_id,
        sender_device_id: params.sender_device_id,
        recipient_device_id: params.recipient_device_id,
        classical_ephemeral_public_key: ephemeral_public,
        pqc_ciphertext,
        transcript_hash,
        encrypted_payload: ciphertext.as_ref().to_vec(),
        nonce: *nonce.as_bytes(),
        expires_at: params.expires_at,
    })
}

/// Open and decrypt a transfer envelope.
///
/// # Contract
///
/// ## Preconditions
/// - The envelope must be syntactically complete and match the recipient keys.
/// - `seen` must be the caller's persistent replay store for the receive
///   context.
///
/// ## Postconditions
/// - Returns plaintext only after validation and AEAD authentication.
/// - Expired envelopes return `Err(ExpiredEnvelope)` before key derivation.
/// - Replayed envelope IDs return `Err(ReplayedEnvelopeId)` after AEAD
///   decryption and sender signature verification.
///
/// ## Invariants
/// - Fail closed; never returns partial plaintext on any error.
/// - Returns a secret-bearing payload wrapper rather than an owned `Vec<u8>`.
pub fn open_envelope(
    envelope: &TransferEnvelope,
    params: OpenEnvelopeParams,
    seen: &mut SeenEnvelopeIds,
) -> Result<SecretPayload, TransferError> {
    let anonymous_recipient_public_key = envelope
        .recipient_device_id
        .is_none()
        .then_some(&params.recipient_classical_public_key);
    validate_envelope(envelope, anonymous_recipient_public_key)?;

    let transfer_key = hybrid::receive_transfer_key(
        &params.recipient_classical_private_key,
        &params.recipient_classical_public_key,
        &envelope.classical_ephemeral_public_key,
        &envelope.pqc_ciphertext,
        &params.recipient_pqc_private_key,
        &envelope.transcript_hash,
    )
    .map_err(|_| TransferError::KeyDerivationFailed)?;
    let nonce = XChaCha20Nonce::from_bytes(envelope.nonce);
    let ciphertext = Ciphertext::from(envelope.encrypted_payload.clone());
    let plaintext = aead::decrypt(
        &transfer_key,
        &nonce,
        &ciphertext,
        &envelope.transcript_hash,
    )
    .map_err(|_| TransferError::DecryptionFailed)?;
    let plaintext = SecretPayload::new(plaintext.as_ref().to_vec());
    let (signature, payload) = decode_signed_payload(plaintext)?;

    mldsa::verify_with_domain(
        params.sender_signing_public_key.signing_public_key(),
        TRANSFER_ENVELOPE_SIGNING_DOMAIN,
        &envelope.transcript_hash,
        &signature,
    )
    .map_err(|_| TransferError::VerificationFailed)?;
    seen.check_and_insert(&envelope.envelope_id, envelope.expires_at)?;

    Ok(payload)
}

#[must_use]
pub fn envelope_to_bytes(envelope: &TransferEnvelope) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(TRANSFER_ENVELOPE_MAGIC);
    out.extend_from_slice(&envelope.version.to_le_bytes());
    out.extend_from_slice(&envelope.transfer_profile.to_u16().to_le_bytes());
    out.extend_from_slice(&envelope.envelope_id);
    out.extend_from_slice(&envelope.sender_device_id);
    if let Some(recipient_device_id) = envelope.recipient_device_id {
        out.push(1);
        out.extend_from_slice(&recipient_device_id);
    } else {
        out.push(0);
    }
    out.extend_from_slice(envelope.classical_ephemeral_public_key.as_slice());
    let pqc_ct_len = u32::try_from(envelope.pqc_ciphertext.as_slice().len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&pqc_ct_len.to_le_bytes());
    out.extend_from_slice(envelope.pqc_ciphertext.as_slice());
    out.extend_from_slice(&envelope.transcript_hash);
    out.extend_from_slice(&envelope.nonce);
    if let Some(expires_at) = envelope.expires_at {
        out.push(1);
        out.extend_from_slice(&expires_at.to_le_bytes());
    } else {
        out.push(0);
    }
    let payload_len = u32::try_from(envelope.encrypted_payload.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&envelope.encrypted_payload);
    out
}

/// Parse an untrusted transfer envelope from bytes.
///
/// # Contract
///
/// ## Preconditions
/// - `bytes` is untrusted external input received from disk, transfer, or a
///   caller boundary.
///
/// ## Postconditions
/// - Returns a `TransferEnvelope` only for the canonical XFER-1 wire layout.
/// - Rejects wrong magic, unsupported version, malformed length fields,
///   truncation, and trailing garbage before key derivation or plaintext
///   release.
///
/// ## Invariants
/// - This parse step does not authenticate the sender, derive keys, or
///   decrypt payload bytes.
/// - The parse path routes through `UntrustedTransferEnvelope::validate_for_open`
///   before returning a `TransferEnvelope`.
pub fn envelope_from_bytes(bytes: &[u8]) -> Result<TransferEnvelope, TransferError> {
    UntrustedTransferEnvelope::validate_for_open(bytes).map(|envelope| envelope.envelope)
}

fn parse_envelope_bytes(bytes: &[u8]) -> Result<TransferEnvelope, TransferError> {
    let mut parser = EnvelopeByteParser::new(bytes);
    if parser.take(TRANSFER_ENVELOPE_MAGIC.len())? != TRANSFER_ENVELOPE_MAGIC {
        return Err(TransferError::UnknownProfile);
    }
    let version = parser.take_u16_le()?;
    if version != 1 {
        return Err(TransferError::UnknownProfile);
    }
    let transfer_profile = TransferProfileId::from_u16(parser.take_u16_le()?)?;
    let envelope_id = parser.take_array()?;
    let sender_device_id = parser.take_array()?;
    let recipient_device_id = match parser.take_u8()? {
        0 => None,
        1 => Some(parser.take_array()?),
        _ => return Err(TransferError::UnknownProfile),
    };
    let classical_ephemeral_public_key = X25519PublicKey::from_bytes(parser.take_array()?);
    let pqc_ct_len = parser.take_u32_le()? as usize;
    if pqc_ct_len != 1088 {
        return Err(TransferError::UnknownProfile);
    }
    let pqc_ciphertext = MlKemCiphertext::from_bytes(
        parser
            .take(pqc_ct_len)?
            .try_into()
            .map_err(|_| TransferError::UnknownProfile)?,
    );
    let transcript_hash = parser.take_array()?;
    let nonce = parser.take_array()?;
    let expires_at = match parser.take_u8()? {
        0 => None,
        1 => Some(parser.take_u64_le()?),
        _ => return Err(TransferError::UnknownProfile),
    };
    let payload_len = parser.take_u32_le()? as usize;
    if payload_len == 0 {
        return Err(TransferError::UnknownProfile);
    }
    let encrypted_payload = parser.take(payload_len)?.to_vec();
    if !parser.is_empty() {
        return Err(TransferError::UnknownProfile);
    }

    Ok(TransferEnvelope {
        version,
        transfer_profile,
        envelope_id,
        sender_device_id,
        recipient_device_id,
        classical_ephemeral_public_key,
        pqc_ciphertext,
        transcript_hash,
        encrypted_payload,
        nonce,
        expires_at,
    })
}

struct EnvelopeByteParser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> EnvelopeByteParser<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], TransferError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(TransferError::UnknownProfile)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(TransferError::UnknownProfile)?;
        self.offset = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8, TransferError> {
        Ok(*self.take(1)?.first().ok_or(TransferError::UnknownProfile)?)
    }

    fn take_u16_le(&mut self) -> Result<u16, TransferError> {
        Ok(u16::from_le_bytes(self.take_array()?))
    }

    fn take_u32_le(&mut self) -> Result<u32, TransferError> {
        Ok(u32::from_le_bytes(self.take_array()?))
    }

    fn take_u64_le(&mut self) -> Result<u64, TransferError> {
        Ok(u64::from_le_bytes(self.take_array()?))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], TransferError> {
        self.take(N)?
            .try_into()
            .map_err(|_| TransferError::UnknownProfile)
    }
}

fn unix_time_millis() -> Timestamp {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    Timestamp::try_from(millis).unwrap_or(Timestamp::MAX)
}

/// Encode the algorithm-tagged signature prefix plus plaintext payload.
///
/// # Contract
///
/// ## Preconditions
/// - `signature` must authenticate the transcript hash under
///   `TRANSFER_ENVELOPE_SIGNING_DOMAIN`.
/// - `plaintext_payload` contains secret plaintext bytes and must not be cloned
///   or exposed through additional raw-byte accessors.
///
/// ## Postconditions
/// - Returns `signature.algorithm:u16le || signature_len:u32le ||
///   signature_bytes || plaintext_payload`.
/// - Returns `Err` without partial output if the signature length cannot fit in
///   `u32`.
///
/// ## Invariants
/// - Consumes `SecretPayload` and returns `SecretPayload`, not raw plaintext
///   `Vec<u8>`.
fn encode_signed_payload(
    signature: &Signature,
    plaintext_payload: SecretPayload,
) -> Result<SecretPayload, TransferError> {
    let signature_len =
        u32::try_from(signature.as_bytes().len()).map_err(|_| TransferError::SigningFailed)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&signature.algorithm().to_le_bytes());
    encoded.extend_from_slice(&signature_len.to_le_bytes());
    encoded.extend_from_slice(signature.as_bytes());
    plaintext_payload.with_secret(|payload| encoded.extend_from_slice(payload));
    Ok(SecretPayload::new(encoded))
}

/// Decode the algorithm-tagged signature prefix and borrowed plaintext suffix.
///
/// # Contract
///
/// ## Preconditions
/// - `bytes` must be a fully authenticated AEAD plaintext produced by
///   `encode_signed_payload`.
///
/// ## Postconditions
/// - Returns the parsed signature plus the remaining payload suffix.
/// - Returns `Err(VerificationFailed)` on malformed framing, truncation, or an
///   unknown signing algorithm identifier.
///
/// ## Invariants
/// - Returns a secret-bearing payload wrapper instead of a borrowed raw byte
///   slice.
fn decode_signed_payload(
    bytes: SecretPayload,
) -> Result<(Signature, SecretPayload), TransferError> {
    let bytes = bytes.into_inner();
    let header = bytes.get(..6).ok_or(TransferError::VerificationFailed)?;
    let algorithm = SigningAlgorithmId::from_le_bytes(
        header
            .get(0..2)
            .ok_or(TransferError::VerificationFailed)?
            .try_into()
            .map_err(|_| TransferError::VerificationFailed)?,
    )
    .map_err(|_| TransferError::VerificationFailed)?;
    let signature_len = u32::from_le_bytes(
        header
            .get(2..6)
            .ok_or(TransferError::VerificationFailed)?
            .try_into()
            .map_err(|_| TransferError::VerificationFailed)?,
    ) as usize;
    let signature_end = 6usize
        .checked_add(signature_len)
        .ok_or(TransferError::VerificationFailed)?;
    let signature_bytes = bytes
        .get(6..signature_end)
        .ok_or(TransferError::VerificationFailed)?
        .to_vec();
    let payload = bytes
        .get(signature_end..)
        .ok_or(TransferError::VerificationFailed)?
        .to_vec();

    let signature = Signature::try_new(algorithm, signature_bytes)
        .map_err(|_| TransferError::VerificationFailed)?;
    Ok((signature, SecretPayload::new(payload)))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        keys::device::{
            DeviceIdentity, DeviceTrustState, Timestamp, DEVICE_ENROLLMENT_SIGNING_DOMAIN,
        },
        transfer::protocol::{CLASSICAL_ALG_ID_X25519, PQC_ALG_ID_MLKEM768},
    };
    use meissnerseal_crypto::types::Key;
    use meissnerseal_pqc::mldsa::{self, SigningAlgorithmId, SigningPrivateKey};

    const PAYLOAD: &[u8] = b"xfer phase1 payload";

    #[test]
    fn compute_transcript_hash_produces_32_byte_output() {
        let fixture = TranscriptFixture::new();
        let params = fixture.params();

        assert_eq!(compute_transcript_hash(&params).len(), 32);
    }

    #[test]
    fn compute_transcript_hash_changes_when_bound_fields_change() {
        let identified = TranscriptFixture::new();
        let identified_baseline = compute_transcript_hash(&identified.params());
        for (label, params) in [
            (
                "sender_device_id",
                identified.with_sender_device_id([0x91; 16]).params(),
            ),
            (
                "sender_classical_ephemeral_public_key",
                identified
                    .with_sender_classical_ephemeral_public_key(Key::from_bytes([0x92; 32]))
                    .params(),
            ),
            (
                "recipient_device_id",
                identified.with_recipient_device_id([0x93; 16]).params(),
            ),
            (
                "pqc_ciphertext",
                identified
                    .with_pqc_ciphertext(Key::from_bytes([0x94; 1088]))
                    .params(),
            ),
            (
                "classical_algorithm_id",
                identified.with_classical_algorithm_id(0x0002).params(),
            ),
            (
                "pqc_algorithm_id",
                identified.with_pqc_algorithm_id(0x0002).params(),
            ),
        ] {
            assert_ne!(
                identified_baseline,
                compute_transcript_hash(&params),
                "identified branch must bind {label}"
            );
        }

        let anonymous = TranscriptFixture::anonymous();
        let anonymous_baseline = compute_transcript_hash(&anonymous.params());
        for (label, params) in [
            (
                "sender_device_id",
                anonymous.with_sender_device_id([0xA1; 16]).params(),
            ),
            (
                "sender_classical_ephemeral_public_key",
                anonymous
                    .with_sender_classical_ephemeral_public_key(Key::from_bytes([0xA2; 32]))
                    .params(),
            ),
            (
                "anonymous_recipient_public_key",
                anonymous
                    .with_anonymous_recipient_public_key(Key::from_bytes([0xA3; 32]))
                    .params(),
            ),
            (
                "pqc_ciphertext",
                anonymous
                    .with_pqc_ciphertext(Key::from_bytes([0xA4; 1088]))
                    .params(),
            ),
            (
                "classical_algorithm_id",
                anonymous.with_classical_algorithm_id(0x0002).params(),
            ),
            (
                "pqc_algorithm_id",
                anonymous.with_pqc_algorithm_id(0x0002).params(),
            ),
        ] {
            assert_ne!(
                anonymous_baseline,
                compute_transcript_hash(&params),
                "anonymous branch must bind {label}"
            );
        }
    }

    #[test]
    fn validate_envelope_rejects_expired_envelope_before_key_derivation() {
        let mut envelope = envelope_fixture();
        envelope.expires_at = Some(past_timestamp());

        assert_eq!(
            validate_envelope(&envelope, None),
            Err(TransferError::ExpiredEnvelope)
        );
    }

    #[test]
    fn validate_envelope_rejects_unknown_transfer_profile() {
        let mut envelope = envelope_fixture();
        envelope.transfer_profile = TransferProfileId::test_only_unchecked(0x0002);

        assert_eq!(
            validate_envelope(&envelope, None),
            Err(TransferError::UnknownProfile)
        );
    }

    #[test]
    fn validate_envelope_rejects_transcript_hash_mismatch() {
        let mut envelope = envelope_fixture();
        envelope.transcript_hash = [0xA5; 32];

        assert_eq!(
            validate_envelope(&envelope, None),
            Err(TransferError::TranscriptMismatch)
        );
    }

    #[test]
    fn transfer_signing_domain_is_distinct_from_device_domain() {
        assert_ne!(
            TRANSFER_ENVELOPE_SIGNING_DOMAIN,
            DEVICE_ENROLLMENT_SIGNING_DOMAIN
        );

        let private_key = SigningPrivateKey::try_new(SigningAlgorithmId::Ed25519V1, vec![0x42; 32])
            .expect("test: valid 32-byte Ed25519V1 seed");
        let mut transfer_message = Vec::new();
        transfer_message.extend_from_slice(TRANSFER_ENVELOPE_SIGNING_DOMAIN);
        transfer_message.extend_from_slice(PAYLOAD);
        let mut device_message = Vec::new();
        device_message.extend_from_slice(DEVICE_ENROLLMENT_SIGNING_DOMAIN);
        device_message.extend_from_slice(PAYLOAD);

        let transfer_sig = mldsa::sign(&private_key, &transfer_message).expect("transfer sign");
        let device_sig = mldsa::sign(&private_key, &device_message).expect("device sign");

        assert_ne!(transfer_sig.as_bytes(), device_sig.as_bytes());
    }

    #[test]
    fn create_envelope_with_expired_expires_at_returns_err() {
        let params = create_params(Some(past_timestamp()));

        assert_eq!(
            create_envelope(params).err(),
            Some(TransferError::ExpiredEnvelope)
        );
    }

    #[test]
    fn open_envelope_with_expired_expires_at_returns_err_before_output() {
        let mut envelope = envelope_fixture();
        envelope.expires_at = Some(past_timestamp());
        let params = open_params();

        assert_eq!(
            open_envelope(&envelope, params, &mut SeenEnvelopeIds::new()).err(),
            Some(TransferError::ExpiredEnvelope)
        );
    }

    #[test]
    fn open_envelope_rejects_replayed_id() {
        let (recipient_private, recipient_public) = hybrid::x25519_keypair();
        let (recipient_pqc_public, recipient_pqc_private) =
            mlkem::keypair().expect("recipient ML-KEM keypair");
        let (sender_signing_public_key, sender_signing_private_key) = mldsa::ed25519_keypair();
        let recipient_private_bytes = *recipient_private.as_bytes();
        let recipient_public_bytes = *recipient_public.as_bytes();
        let recipient_pqc_private_bytes = *recipient_pqc_private.as_bytes();
        let envelope = create_envelope(CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: Some([0x22; 16]),
            anonymous_recipient_public_key: None,
            recipient_classical_public_key: recipient_public,
            recipient_pqc_public_key: recipient_pqc_public,
            sender_signing_private_key,
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        })
        .expect("create envelope");
        let mut seen = SeenEnvelopeIds::new();

        let first = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(recipient_private_bytes),
                recipient_classical_public_key: Key::from_bytes(recipient_public_bytes),
                recipient_pqc_private_key: Key::from_bytes(recipient_pqc_private_bytes),
                sender_signing_public_key: trusted_sender(sender_signing_public_key.clone()),
            },
            &mut seen,
        )
        .expect("first open");
        first.with_secret(|payload| assert_eq!(payload, PAYLOAD));

        let second = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(recipient_private_bytes),
                recipient_classical_public_key: Key::from_bytes(recipient_public_bytes),
                recipient_pqc_private_key: Key::from_bytes(recipient_pqc_private_bytes),
                sender_signing_public_key: trusted_sender(sender_signing_public_key),
            },
            &mut seen,
        );

        assert!(matches!(second, Err(TransferError::ReplayedEnvelopeId)));
    }

    #[test]
    fn open_envelope_evicts_expired_replay_entry_before_checking_replay() {
        let (recipient_private, recipient_public) = hybrid::x25519_keypair();
        let (recipient_pqc_public, recipient_pqc_private) =
            mlkem::keypair().expect("recipient ML-KEM keypair");
        let (sender_signing_public_key, sender_signing_private_key) = mldsa::ed25519_keypair();
        let recipient_private_bytes = *recipient_private.as_bytes();
        let recipient_public_bytes = *recipient_public.as_bytes();
        let recipient_pqc_private_bytes = *recipient_pqc_private.as_bytes();
        let envelope = create_envelope(CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: Some([0x22; 16]),
            anonymous_recipient_public_key: None,
            recipient_classical_public_key: recipient_public,
            recipient_pqc_public_key: recipient_pqc_public,
            sender_signing_private_key,
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        })
        .expect("create envelope");

        // Pre-populate a replay store with this envelope's ID but marked as expired.
        // from_bytes is used to bypass check_and_insert's own expiry guard.
        let mut store_bytes = Vec::new();
        store_bytes.extend_from_slice(&1u32.to_le_bytes());
        store_bytes.extend_from_slice(&envelope.envelope_id);
        store_bytes.extend_from_slice(&past_timestamp().to_le_bytes());
        let mut seen = SeenEnvelopeIds::from_bytes(&store_bytes).expect("expired-entry fixture");

        // open_envelope calls check_and_insert, which calls evict_expired first.
        // The expired entry is removed before the replay check, so the call must succeed.
        let result = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(recipient_private_bytes),
                recipient_classical_public_key: Key::from_bytes(recipient_public_bytes),
                recipient_pqc_private_key: Key::from_bytes(recipient_pqc_private_bytes),
                sender_signing_public_key: trusted_sender(sender_signing_public_key),
            },
            &mut seen,
        );
        assert!(
            result.is_ok(),
            "open_envelope must succeed: evict_expired must remove expired entry before replay check"
        );
    }

    #[test]
    fn open_envelope_auth_failure_must_not_poison_replay_store() {
        let (recipient_private, recipient_public) = hybrid::x25519_keypair();
        let (recipient_pqc_public, recipient_pqc_private) =
            mlkem::keypair().expect("recipient ML-KEM keypair");
        let (sender_signing_public_key, sender_signing_private_key) = mldsa::ed25519_keypair();
        let recipient_private_bytes = *recipient_private.as_bytes();
        let recipient_public_bytes = *recipient_public.as_bytes();
        let recipient_pqc_private_bytes = *recipient_pqc_private.as_bytes();
        let mut envelope = create_envelope(CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: Some([0x22; 16]),
            anonymous_recipient_public_key: None,
            recipient_classical_public_key: recipient_public.clone(),
            recipient_pqc_public_key: recipient_pqc_public,
            sender_signing_private_key,
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        })
        .expect("create envelope");
        let last = envelope
            .encrypted_payload
            .last_mut()
            .expect("encrypted payload fixture");
        *last ^= 0x01;

        let mut seen = SeenEnvelopeIds::new();
        let first = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(recipient_private_bytes),
                recipient_classical_public_key: Key::from_bytes(recipient_public_bytes),
                recipient_pqc_private_key: Key::from_bytes(recipient_pqc_private_bytes),
                sender_signing_public_key: trusted_sender(sender_signing_public_key.clone()),
            },
            &mut seen,
        );
        let second = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(recipient_private_bytes),
                recipient_classical_public_key: Key::from_bytes(recipient_public_bytes),
                recipient_pqc_private_key: Key::from_bytes(recipient_pqc_private_bytes),
                sender_signing_public_key: trusted_sender(sender_signing_public_key),
            },
            &mut seen,
        );

        assert!(matches!(first, Err(TransferError::DecryptionFailed)));
        assert!(
            matches!(second, Err(TransferError::DecryptionFailed)),
            "auth failure must not store envelope_id in replay set"
        );
    }

    #[test]
    fn envelope_to_bytes_roundtrip_preserves_fields() {
        let envelope = envelope_fixture();
        let parsed = envelope_from_bytes(&envelope_to_bytes(&envelope)).expect("parse");

        assert_eq!(parsed.version, envelope.version);
        assert_eq!(parsed.transfer_profile, envelope.transfer_profile);
        assert_eq!(parsed.envelope_id, envelope.envelope_id);
        assert_eq!(parsed.sender_device_id, envelope.sender_device_id);
        assert_eq!(parsed.recipient_device_id, envelope.recipient_device_id);
        assert_eq!(
            parsed.classical_ephemeral_public_key.as_slice(),
            envelope.classical_ephemeral_public_key.as_slice()
        );
        assert_eq!(
            parsed.pqc_ciphertext.as_slice(),
            envelope.pqc_ciphertext.as_slice()
        );
        assert_eq!(parsed.transcript_hash, envelope.transcript_hash);
        assert_eq!(parsed.encrypted_payload, envelope.encrypted_payload);
        assert_eq!(parsed.nonce, envelope.nonce);
        assert_eq!(parsed.expires_at, envelope.expires_at);
    }

    #[test]
    fn envelope_from_bytes_rejects_pqc_ct_len_overrun() {
        let envelope = envelope_fixture();
        let mut bytes = envelope_to_bytes(&envelope);
        let pqc_len_offset = 6 + 2 + 2 + 16 + 16 + 1 + 16 + 32;
        bytes
            .get_mut(pqc_len_offset..pqc_len_offset + 4)
            .expect("pqc_ct_len field within bytes")
            .copy_from_slice(&u32::MAX.to_le_bytes());

        assert!(matches!(
            envelope_from_bytes(&bytes),
            Err(TransferError::UnknownProfile)
        ));
    }

    #[test]
    fn envelope_from_bytes_rejects_payload_len_overrun() {
        let envelope = envelope_fixture();
        let mut bytes = envelope_to_bytes(&envelope);
        let payload_len_offset = bytes.len() - envelope.encrypted_payload.len() - 4;
        bytes
            .get_mut(payload_len_offset..payload_len_offset + 4)
            .expect("payload_len field within bytes")
            .copy_from_slice(&u32::MAX.to_le_bytes());

        assert!(matches!(
            envelope_from_bytes(&bytes),
            Err(TransferError::UnknownProfile)
        ));
    }

    #[test]
    fn envelope_from_bytes_table_driven_parser_rejects_malformed_inputs_before_crypto() {
        let envelope = envelope_fixture();
        let bytes = envelope_to_bytes(&envelope);
        let payload_len_offset = bytes.len() - envelope.encrypted_payload.len() - 4;
        let version_offset = TRANSFER_ENVELOPE_MAGIC.len();
        let recipient_flag_offset = 6 + 2 + 2 + 16 + 16;
        let pqc_len_offset = 6 + 2 + 2 + 16 + 16 + 1 + 16 + 32;

        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        for index in 0..TRANSFER_ENVELOPE_MAGIC.len() {
            let mut mutated = bytes.clone();
            *mutated.get_mut(index).expect("magic byte offset in bounds") ^= 0xFF;
            cases.push(("wrong_magic", mutated));
        }
        let mut invalid_recipient_flag = bytes.clone();
        *invalid_recipient_flag
            .get_mut(recipient_flag_offset)
            .expect("recipient flag offset in bounds") = 0x02;
        cases.push(("invalid_recipient_flag", invalid_recipient_flag));

        let mut invalid_version = bytes.clone();
        invalid_version
            .get_mut(version_offset..version_offset + 2)
            .expect("version field in bounds")
            .copy_from_slice(&2u16.to_le_bytes());
        cases.push(("unsupported_version", invalid_version));

        let mut zero_payload_len = bytes.clone();
        zero_payload_len
            .get_mut(payload_len_offset..payload_len_offset + 4)
            .expect("payload_len field in bounds")
            .copy_from_slice(&0u32.to_le_bytes());
        cases.push(("payload_len_zero", zero_payload_len));

        let mut payload_len_too_large = bytes.clone();
        payload_len_too_large
            .get_mut(payload_len_offset..payload_len_offset + 4)
            .expect("payload_len field in bounds")
            .copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(("payload_len_overrun", payload_len_too_large));

        let mut wrong_pqc_len = bytes.clone();
        wrong_pqc_len
            .get_mut(pqc_len_offset..pqc_len_offset + 4)
            .expect("pqc_ct_len field in bounds")
            .copy_from_slice(&1087u32.to_le_bytes());
        cases.push(("pqc_ct_len_not_1088", wrong_pqc_len));

        for (id, bytes) in cases {
            assert!(
                matches!(
                    envelope_from_bytes(&bytes),
                    Err(TransferError::UnknownProfile)
                ),
                "case {id}: parser must fail closed"
            );
        }
    }

    #[test]
    fn open_envelope_rejects_tampered_nonce_with_auth_error() {
        let (recipient_private, recipient_public) = hybrid::x25519_keypair();
        let (recipient_pqc_public, recipient_pqc_private) =
            mlkem::keypair().expect("recipient ML-KEM keypair");
        let (sender_signing_public_key, sender_signing_private_key) = mldsa::ed25519_keypair();
        let mut envelope = create_envelope(CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: Some([0x22; 16]),
            anonymous_recipient_public_key: None,
            recipient_classical_public_key: recipient_public.clone(),
            recipient_pqc_public_key: recipient_pqc_public,
            sender_signing_private_key,
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        })
        .expect("create envelope");
        envelope.nonce[0] ^= 0x01;

        let result = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(*recipient_private.as_bytes()),
                recipient_classical_public_key: Key::from_bytes(*recipient_public.as_bytes()),
                recipient_pqc_private_key: Key::from_bytes(*recipient_pqc_private.as_bytes()),
                sender_signing_public_key: trusted_sender(sender_signing_public_key),
            },
            &mut SeenEnvelopeIds::new(),
        );

        assert!(matches!(result, Err(TransferError::DecryptionFailed)));
    }

    #[test]
    fn anonymous_create_then_open_roundtrips_plaintext() {
        let (recipient_private, recipient_public) = hybrid::x25519_keypair();
        let (recipient_pqc_public, recipient_pqc_private) =
            mlkem::keypair().expect("recipient ML-KEM keypair");
        let (sender_signing_public_key, sender_signing_private_key) = mldsa::ed25519_keypair();
        let envelope = create_envelope(CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: None,
            anonymous_recipient_public_key: Some(recipient_public.clone()),
            recipient_classical_public_key: recipient_public.clone(),
            recipient_pqc_public_key: recipient_pqc_public,
            sender_signing_private_key,
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        })
        .expect("create anonymous envelope");

        let payload = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(*recipient_private.as_bytes()),
                recipient_classical_public_key: Key::from_bytes(*recipient_public.as_bytes()),
                recipient_pqc_private_key: Key::from_bytes(*recipient_pqc_private.as_bytes()),
                sender_signing_public_key: trusted_sender(sender_signing_public_key),
            },
            &mut SeenEnvelopeIds::new(),
        )
        .expect("open anonymous envelope");

        payload.with_secret(|bytes| assert_eq!(bytes, PAYLOAD));
    }

    #[test]
    fn create_envelope_rejects_anonymous_mode_without_public_key_binding() {
        let params = CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: None,
            anonymous_recipient_public_key: None,
            recipient_classical_public_key: Key::from_bytes([0x44; 32]),
            recipient_pqc_public_key: Key::from_bytes([0x55; 1184]),
            sender_signing_private_key: SigningPrivateKey::try_new(
                SigningAlgorithmId::Ed25519V1,
                vec![0x42; 32],
            )
            .expect("test: valid 32-byte Ed25519V1 seed"),
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        };

        assert!(matches!(
            create_envelope(params),
            Err(TransferError::MissingAnonymousRecipientPublicKey)
        ));
    }

    #[test]
    fn validate_envelope_named_recipient_succeeds() {
        let envelope = envelope_fixture();

        assert_eq!(validate_envelope(&envelope, None), Ok(()));
    }

    #[test]
    fn validate_envelope_rejects_mutated_anonymous_recipient_public_key() {
        let mut envelope = envelope_fixture();
        envelope.recipient_device_id = None;
        let anonymous_recipient_public_key = Key::from_bytes([0x44; 32]);
        envelope.transcript_hash = compute_transcript_hash(&TranscriptParams {
            transfer_profile: envelope.transfer_profile,
            sender_device_id: &envelope.sender_device_id,
            sender_classical_ephemeral_public_key: &envelope.classical_ephemeral_public_key,
            recipient_device_id: None,
            anonymous_recipient_public_key: Some(&anonymous_recipient_public_key),
            pqc_ciphertext: &envelope.pqc_ciphertext,
            classical_algorithm_id: CLASSICAL_ALG_ID_X25519,
            pqc_algorithm_id: PQC_ALG_ID_MLKEM768,
            envelope_id: &envelope.envelope_id,
            expires_at: envelope.expires_at,
        });

        let mutated = Key::from_bytes([0x45; 32]);

        assert_eq!(
            validate_envelope(&envelope, Some(&mutated)),
            Err(TransferError::TranscriptMismatch)
        );
    }

    #[test]
    fn anonymous_open_rejects_different_recipient_public_key_with_transcript_mismatch() {
        let (recipient_private, recipient_public) = hybrid::x25519_keypair();
        let (recipient_pqc_public, recipient_pqc_private) =
            mlkem::keypair().expect("recipient ML-KEM keypair");
        let (sender_signing_public_key, sender_signing_private_key) = mldsa::ed25519_keypair();
        let envelope = create_envelope(CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: None,
            anonymous_recipient_public_key: Some(recipient_public.clone()),
            recipient_classical_public_key: recipient_public,
            recipient_pqc_public_key: recipient_pqc_public,
            sender_signing_private_key,
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        })
        .expect("create anonymous envelope");

        let result = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(*recipient_private.as_bytes()),
                recipient_classical_public_key: Key::from_bytes([0x99; 32]),
                recipient_pqc_private_key: Key::from_bytes(*recipient_pqc_private.as_bytes()),
                sender_signing_public_key: trusted_sender(sender_signing_public_key),
            },
            &mut SeenEnvelopeIds::new(),
        );

        assert!(matches!(result, Err(TransferError::TranscriptMismatch)));
    }

    #[test]
    fn validate_envelope_rejects_unsupported_version() {
        let mut envelope = envelope_fixture();
        envelope.version = 0xFFFF;

        assert_eq!(
            validate_envelope(&envelope, None),
            Err(TransferError::UnknownProfile)
        );
    }

    #[test]
    fn envelope_from_bytes_rejects_truncated_input() {
        let bytes = &TRANSFER_ENVELOPE_MAGIC[..4];

        assert!(matches!(
            envelope_from_bytes(bytes),
            Err(TransferError::UnknownProfile)
        ));
    }

    #[test]
    fn envelope_from_bytes_rejects_trailing_garbage() {
        let mut envelope = envelope_fixture();
        // Make the serialized bytes deterministic by replacing the time-based
        // expiry field with a fixed value before appending trailing garbage.
        envelope.expires_at = Some(u64::MAX / 2);
        let mut bytes = envelope_to_bytes(&envelope);
        bytes.push(0xAA);

        assert!(matches!(
            envelope_from_bytes(&bytes),
            Err(TransferError::UnknownProfile)
        ));
    }

    #[test]
    fn envelope_from_bytes_accepts_valid_bytes() {
        let envelope = envelope_fixture();

        assert!(envelope_from_bytes(&envelope_to_bytes(&envelope)).is_ok());
    }

    #[test]
    fn untrusted_transfer_envelope_validate_for_open_checks_expiry_and_flags() {
        let mut envelope = envelope_fixture();
        envelope.expires_at = Some(past_timestamp());
        assert!(matches!(
            UntrustedTransferEnvelope::validate_for_open(&envelope_to_bytes(&envelope)),
            Err(TransferError::ExpiredEnvelope)
        ));

        let mut bytes = envelope_to_bytes(&envelope_fixture());
        let recipient_flag_offset = 6 + 2 + 2 + 16 + 16;
        *bytes
            .get_mut(recipient_flag_offset)
            .expect("recipient flag offset in bounds") = 0x02;
        assert!(matches!(
            UntrustedTransferEnvelope::validate_for_open(&bytes),
            Err(TransferError::UnknownProfile)
        ));
    }

    #[test]
    fn anonymous_untrusted_transfer_envelope_validate_for_open_rejects_expiry() {
        let mut envelope = envelope_fixture();
        envelope.recipient_device_id = None;
        envelope.expires_at = Some(past_timestamp());

        assert!(matches!(
            UntrustedTransferEnvelope::validate_for_open(&envelope_to_bytes(&envelope)),
            Err(TransferError::ExpiredEnvelope)
        ));
    }

    #[test]
    fn create_envelope_success_invariants_roundtrip_and_distinct_ids() {
        let first = create_envelope(CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: Some([0x22; 16]),
            anonymous_recipient_public_key: None,
            recipient_classical_public_key: Key::from_bytes([0x44; 32]),
            recipient_pqc_public_key: Key::from_bytes([0x55; 1184]),
            sender_signing_private_key: SigningPrivateKey::try_new(
                SigningAlgorithmId::Ed25519V1,
                vec![0x42; 32],
            )
            .expect("test: valid 32-byte Ed25519V1 seed"),
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        })
        .expect("create first envelope");
        let second = create_envelope(CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: Some([0x22; 16]),
            anonymous_recipient_public_key: None,
            recipient_classical_public_key: Key::from_bytes([0x44; 32]),
            recipient_pqc_public_key: Key::from_bytes([0x55; 1184]),
            sender_signing_private_key: SigningPrivateKey::try_new(
                SigningAlgorithmId::Ed25519V1,
                vec![0x43; 32],
            )
            .expect("test: valid 32-byte Ed25519V1 seed"),
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        })
        .expect("create second envelope");

        let parsed = envelope_from_bytes(&envelope_to_bytes(&first)).expect("parse first envelope");
        assert_eq!(
            parsed.envelope_id, first.envelope_id,
            "envelope_id round-trips"
        );
        assert_ne!(
            first.envelope_id, second.envelope_id,
            "envelope ids must be unique"
        );
        assert_eq!(parsed.recipient_device_id, Some([0x22; 16]));
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.transfer_profile, TransferProfileId::v1());
        assert_eq!(parsed.expires_at, first.expires_at);
        assert!(
            !parsed.encrypted_payload.is_empty(),
            "ciphertext must not be empty"
        );
    }

    #[test]
    fn open_envelope_wrong_sender_key_returns_verification_failed_and_does_not_mutate_replay_store()
    {
        let (recipient_private, recipient_public) = hybrid::x25519_keypair();
        let (recipient_pqc_public, recipient_pqc_private) =
            mlkem::keypair().expect("recipient ML-KEM keypair");
        let (_sender_signing_public_key, sender_signing_private_key) = mldsa::ed25519_keypair();
        let (wrong_signing_public_key, _) = mldsa::ed25519_keypair();
        let envelope = create_envelope(CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: Some([0x22; 16]),
            anonymous_recipient_public_key: None,
            recipient_classical_public_key: recipient_public.clone(),
            recipient_pqc_public_key: recipient_pqc_public,
            sender_signing_private_key,
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        })
        .expect("create envelope");
        let mut seen = SeenEnvelopeIds::new();

        let first = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(*recipient_private.as_bytes()),
                recipient_classical_public_key: Key::from_bytes(*recipient_public.as_bytes()),
                recipient_pqc_private_key: Key::from_bytes(*recipient_pqc_private.as_bytes()),
                sender_signing_public_key: trusted_sender(wrong_signing_public_key.clone()),
            },
            &mut seen,
        );
        let second = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(*recipient_private.as_bytes()),
                recipient_classical_public_key: Key::from_bytes(*recipient_public.as_bytes()),
                recipient_pqc_private_key: Key::from_bytes(*recipient_pqc_private.as_bytes()),
                sender_signing_public_key: trusted_sender(wrong_signing_public_key),
            },
            &mut seen,
        );

        assert!(matches!(first, Err(TransferError::VerificationFailed)));
        assert!(matches!(second, Err(TransferError::VerificationFailed)));
    }

    #[test]
    fn open_envelope_wrong_recipient_x25519_private_key_rejects_with_positive_control() {
        let (recipient_private, recipient_public) = hybrid::x25519_keypair();
        let (wrong_private, _wrong_public) = hybrid::x25519_keypair();
        let (recipient_pqc_public, recipient_pqc_private) =
            mlkem::keypair().expect("recipient ML-KEM keypair");
        let (sender_signing_public_key, sender_signing_private_key) = mldsa::ed25519_keypair();
        let envelope = create_envelope(CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: Some([0x22; 16]),
            anonymous_recipient_public_key: None,
            recipient_classical_public_key: recipient_public.clone(),
            recipient_pqc_public_key: recipient_pqc_public,
            sender_signing_private_key,
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        })
        .expect("create envelope");

        let ok = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(*recipient_private.as_bytes()),
                recipient_classical_public_key: Key::from_bytes(*recipient_public.as_bytes()),
                recipient_pqc_private_key: Key::from_bytes(*recipient_pqc_private.as_bytes()),
                sender_signing_public_key: trusted_sender(sender_signing_public_key.clone()),
            },
            &mut SeenEnvelopeIds::new(),
        );
        assert!(ok.is_ok(), "positive control must succeed");

        let wrong = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(*wrong_private.as_bytes()),
                recipient_classical_public_key: Key::from_bytes(*recipient_public.as_bytes()),
                recipient_pqc_private_key: Key::from_bytes(*recipient_pqc_private.as_bytes()),
                sender_signing_public_key: trusted_sender(sender_signing_public_key),
            },
            &mut SeenEnvelopeIds::new(),
        );
        assert!(matches!(wrong, Err(TransferError::DecryptionFailed)));
    }

    #[test]
    fn open_envelope_wrong_mlkem_private_key_rejects_with_positive_control() {
        let (recipient_private, recipient_public) = hybrid::x25519_keypair();
        let (recipient_pqc_public, recipient_pqc_private) =
            mlkem::keypair().expect("recipient ML-KEM keypair");
        let (_wrong_pqc_public, wrong_pqc_private) =
            mlkem::keypair().expect("wrong recipient ML-KEM keypair");
        let (sender_signing_public_key, sender_signing_private_key) = mldsa::ed25519_keypair();
        let envelope = create_envelope(CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: Some([0x22; 16]),
            anonymous_recipient_public_key: None,
            recipient_classical_public_key: recipient_public.clone(),
            recipient_pqc_public_key: recipient_pqc_public,
            sender_signing_private_key,
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        })
        .expect("create envelope");

        let ok = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(*recipient_private.as_bytes()),
                recipient_classical_public_key: Key::from_bytes(*recipient_public.as_bytes()),
                recipient_pqc_private_key: Key::from_bytes(*recipient_pqc_private.as_bytes()),
                sender_signing_public_key: trusted_sender(sender_signing_public_key.clone()),
            },
            &mut SeenEnvelopeIds::new(),
        );
        assert!(ok.is_ok(), "positive control must succeed");

        let wrong = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(*recipient_private.as_bytes()),
                recipient_classical_public_key: Key::from_bytes(*recipient_public.as_bytes()),
                recipient_pqc_private_key: Key::from_bytes(*wrong_pqc_private.as_bytes()),
                sender_signing_public_key: trusted_sender(sender_signing_public_key),
            },
            &mut SeenEnvelopeIds::new(),
        );
        assert!(matches!(wrong, Err(TransferError::DecryptionFailed)));
    }

    #[test]
    fn open_envelope_check_and_insert_runs_after_decryption() {
        let (recipient_private, recipient_public) = hybrid::x25519_keypair();
        let (recipient_pqc_public, recipient_pqc_private) =
            mlkem::keypair().expect("recipient ML-KEM keypair");
        let (sender_signing_public_key, sender_signing_private_key) = mldsa::ed25519_keypair();
        let recipient_private_bytes = *recipient_private.as_bytes();
        let recipient_public_bytes = *recipient_public.as_bytes();
        let recipient_pqc_private_bytes = *recipient_pqc_private.as_bytes();
        let mut envelope = create_envelope(CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: Some([0x22; 16]),
            anonymous_recipient_public_key: None,
            recipient_classical_public_key: recipient_public,
            recipient_pqc_public_key: recipient_pqc_public,
            sender_signing_private_key,
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at: Some(future_timestamp()),
        })
        .expect("create envelope");

        let make_params = || OpenEnvelopeParams {
            recipient_classical_private_key: Key::from_bytes(recipient_private_bytes),
            recipient_classical_public_key: Key::from_bytes(recipient_public_bytes),
            recipient_pqc_private_key: Key::from_bytes(recipient_pqc_private_bytes),
            sender_signing_public_key: trusted_sender(sender_signing_public_key.clone()),
        };

        let mut seen = SeenEnvelopeIds::new();
        open_envelope(&envelope, make_params(), &mut seen).expect("first open must succeed");

        // Tamper the ciphertext so decryption fails on the second call.
        // envelope_id is already in `seen`. If check_and_insert ran BEFORE decrypt,
        // the error would be ReplayedEnvelopeId. The error must be DecryptionFailed,
        // pinning that AEAD decrypt runs before the replay check.
        *envelope
            .encrypted_payload
            .last_mut()
            .expect("payload fixture") ^= 0xFF;
        let err = open_envelope(&envelope, make_params(), &mut seen)
            .expect_err("tampered ciphertext must fail");
        assert!(
            matches!(err, TransferError::DecryptionFailed),
            "expected DecryptionFailed — decrypt must run before replay check; got {err:?}"
        );
    }

    fn envelope_fixture() -> TransferEnvelope {
        let fixture = TranscriptFixture::new();
        let transcript_hash = compute_transcript_hash(&fixture.params());
        // Use fixture.expires_at, not a fresh future_timestamp() call — the
        // transcript hash binds the expiry; a second call to future_timestamp()
        // can return a different millisecond under parallel load, causing
        // TranscriptMismatch on validate_envelope.
        TransferEnvelope {
            version: 1,
            transfer_profile: TransferProfileId::v1(),
            envelope_id: fixture.envelope_id,
            sender_device_id: fixture.sender_device_id,
            recipient_device_id: fixture.recipient_device_id,
            classical_ephemeral_public_key: Key::from_bytes([0x44; 32]),
            pqc_ciphertext: Key::from_bytes([0x55; 1088]),
            transcript_hash,
            encrypted_payload: vec![0x66; 16],
            nonce: [0x77; 24],
            expires_at: fixture.expires_at,
        }
    }

    fn create_params(expires_at: Option<Timestamp>) -> CreateEnvelopeParams {
        CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: Some([0x22; 16]),
            anonymous_recipient_public_key: None,
            recipient_classical_public_key: Key::from_bytes([0x44; 32]),
            recipient_pqc_public_key: Key::from_bytes([0x55; 1184]),
            sender_signing_private_key: SigningPrivateKey::try_new(
                SigningAlgorithmId::Ed25519V1,
                vec![0x42; 32],
            )
            .expect("test: valid 32-byte Ed25519V1 seed"),
            plaintext_payload: SecretPayload::new(PAYLOAD.to_vec()),
            expires_at,
        }
    }

    fn open_params() -> OpenEnvelopeParams {
        OpenEnvelopeParams {
            recipient_classical_private_key: Key::from_bytes([0x88; 32]),
            recipient_classical_public_key: Key::from_bytes([0x44; 32]),
            recipient_pqc_private_key: Key::from_bytes([0x99; 2400]),
            sender_signing_public_key: trusted_sender(
                mldsa::SigningPublicKey::try_new(SigningAlgorithmId::Ed25519V1, vec![0xAA; 32])
                    .expect("test: valid 32-byte Ed25519V1 public key"),
            ),
        }
    }

    fn trusted_sender(signing_public_key: SigningPublicKey) -> TrustedSender {
        TrustedSender::from_verified(&DeviceIdentity {
            device_id: [0x10; 16],
            display_name: "trusted-sender".to_owned(),
            classical_public_key: Key::from_bytes([0x20; 32]),
            pqc_public_key: Key::from_bytes([0x30; 1184]),
            signing_public_key: Some(signing_public_key),
            created_at: future_timestamp(),
            trust_state: DeviceTrustState::Verified,
        })
        .expect("trusted sender fixture")
    }

    #[test]
    fn trusted_sender_rejects_non_eligible_trust_states() {
        let (pk, _) = mldsa::ed25519_keypair();
        for state in [
            DeviceTrustState::Untrusted,
            DeviceTrustState::PendingInbound,
            DeviceTrustState::PendingOutbound,
            DeviceTrustState::Revoked,
            DeviceTrustState::Expired,
        ] {
            let identity = DeviceIdentity {
                device_id: [0x10; 16],
                display_name: "test".to_owned(),
                classical_public_key: Key::from_bytes([0x20; 32]),
                pqc_public_key: Key::from_bytes([0x30; 1184]),
                signing_public_key: Some(pk.clone()),
                created_at: future_timestamp(),
                trust_state: state,
            };
            assert!(
                matches!(
                    TrustedSender::from_verified(&identity),
                    Err(TransferError::UntrustedSender)
                ),
                "expected UntrustedSender for {state:?}"
            );
        }
    }

    #[test]
    fn trusted_sender_rejects_missing_signing_key() {
        for state in [DeviceTrustState::Verified, DeviceTrustState::Approved] {
            let identity = DeviceIdentity {
                device_id: [0x10; 16],
                display_name: "test".to_owned(),
                classical_public_key: Key::from_bytes([0x20; 32]),
                pqc_public_key: Key::from_bytes([0x30; 1184]),
                signing_public_key: None,
                created_at: future_timestamp(),
                trust_state: state,
            };
            assert!(
                matches!(
                    TrustedSender::from_verified(&identity),
                    Err(TransferError::UntrustedSender)
                ),
                "expected UntrustedSender when signing_public_key is None for {state:?}"
            );
        }
    }

    fn now_millis() -> Timestamp {
        Timestamp::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after unix epoch")
                .as_millis(),
        )
        .expect("timestamp fits")
    }

    fn past_timestamp() -> Timestamp {
        now_millis().saturating_sub(1_000)
    }

    fn future_timestamp() -> Timestamp {
        now_millis().checked_add(60_000).expect("timestamp")
    }

    #[derive(Clone)]
    struct TranscriptFixture {
        sender_device_id: DeviceId,
        recipient_device_id: Option<DeviceId>,
        anonymous_recipient_public_key: Option<X25519PublicKey>,
        sender_classical_ephemeral_public_key: X25519PublicKey,
        pqc_ciphertext: MlKemCiphertext,
        envelope_id: EnvelopeId,
        expires_at: Option<Timestamp>,
        classical_algorithm_id: u16,
        pqc_algorithm_id: u16,
    }

    impl TranscriptFixture {
        fn new() -> Self {
            Self {
                sender_device_id: [0x11; 16],
                recipient_device_id: Some([0x22; 16]),
                anonymous_recipient_public_key: None,
                sender_classical_ephemeral_public_key: Key::from_bytes([0x44; 32]),
                pqc_ciphertext: Key::from_bytes([0x55; 1088]),
                envelope_id: [0x33; 16],
                expires_at: Some(future_timestamp()),
                classical_algorithm_id: CLASSICAL_ALG_ID_X25519,
                pqc_algorithm_id: PQC_ALG_ID_MLKEM768,
            }
        }

        fn anonymous() -> Self {
            Self {
                recipient_device_id: None,
                anonymous_recipient_public_key: Some(Key::from_bytes([0x24; 32])),
                ..Self::new()
            }
        }

        fn with_sender_device_id(&self, sender_device_id: DeviceId) -> Self {
            Self {
                sender_device_id,
                ..self.clone()
            }
        }

        fn with_sender_classical_ephemeral_public_key(
            &self,
            sender_classical_ephemeral_public_key: X25519PublicKey,
        ) -> Self {
            Self {
                sender_classical_ephemeral_public_key,
                ..self.clone()
            }
        }

        fn with_recipient_device_id(&self, recipient_device_id: DeviceId) -> Self {
            Self {
                recipient_device_id: Some(recipient_device_id),
                anonymous_recipient_public_key: None,
                ..self.clone()
            }
        }

        fn with_anonymous_recipient_public_key(
            &self,
            anonymous_recipient_public_key: X25519PublicKey,
        ) -> Self {
            Self {
                recipient_device_id: None,
                anonymous_recipient_public_key: Some(anonymous_recipient_public_key),
                ..self.clone()
            }
        }

        fn with_pqc_ciphertext(&self, pqc_ciphertext: MlKemCiphertext) -> Self {
            Self {
                pqc_ciphertext,
                ..self.clone()
            }
        }

        fn with_classical_algorithm_id(&self, classical_algorithm_id: u16) -> Self {
            Self {
                classical_algorithm_id,
                ..self.clone()
            }
        }

        fn with_pqc_algorithm_id(&self, pqc_algorithm_id: u16) -> Self {
            Self {
                pqc_algorithm_id,
                ..self.clone()
            }
        }

        fn params(&self) -> TranscriptParams<'_> {
            TranscriptParams {
                transfer_profile: TransferProfileId::v1(),
                sender_device_id: &self.sender_device_id,
                sender_classical_ephemeral_public_key: &self.sender_classical_ephemeral_public_key,
                recipient_device_id: self.recipient_device_id.as_ref(),
                anonymous_recipient_public_key: self.anonymous_recipient_public_key.as_ref(),
                pqc_ciphertext: &self.pqc_ciphertext,
                classical_algorithm_id: self.classical_algorithm_id,
                pqc_algorithm_id: self.pqc_algorithm_id,
                envelope_id: &self.envelope_id,
                expires_at: self.expires_at,
            }
        }
    }
}
