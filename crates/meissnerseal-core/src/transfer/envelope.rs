// SPDX-License-Identifier: Apache-2.0
//! Transfer envelope data model and XFER-1 operation contracts.

use crate::{
    keys::device::{DeviceId, Timestamp},
    transfer::protocol::{
        EnvelopeId, TransferError, TransferProfileId, CLASSICAL_ALG_ID_X25519, PQC_ALG_ID_MLKEM768,
        TRANSFER_PROFILE_V1_ID,
    },
    transfer::replay::SeenEnvelopeIds,
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

/// Context string for XFER-1 transfer envelope signatures (F-39).
pub const TRANSFER_ENVELOPE_SIGNING_DOMAIN: &[u8] = b"meissnerseal.transfer.envelope.v1\x00";
const TRANSFER_TRANSCRIPT_DOMAIN: &[u8] = b"meissnerseal-transfer-transcript-v1";
const TRANSFER_ENVELOPE_MAGIC: &[u8; 6] = b"MSENV\x01";

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
///   authentication succeeds in Phase 2.
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
/// - Phase 2 transcript hashing must produce 32 bytes of SHA-256 output.
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
/// - Recipient public keys must come from an authenticated `DeviceIdentity`.
/// - `expires_at`, when present, must not be in the past.
///
/// ## Postconditions
/// - Phase 2 returns a sealed envelope or `Err`; it never returns partial
///   ciphertext, transfer keys, or plaintext on failure.
///
/// ## Invariants
/// - Expiry is checked before key derivation.
pub struct CreateEnvelopeParams {
    pub sender_device_id: DeviceId,
    pub recipient_device_id: Option<DeviceId>,
    pub recipient_classical_public_key: X25519PublicKey,
    pub recipient_pqc_public_key: MlKemPublicKey,
    pub sender_signing_private_key: SigningPrivateKey,
    pub plaintext_payload: Vec<u8>,
    pub expires_at: Option<Timestamp>,
}

/// Inputs for opening a sealed transfer envelope.
///
/// # Contract
///
/// ## Preconditions
/// - Recipient private keys must match the public keys bound by the sender's
///   authenticated recipient identity.
/// - Sender signing public key must be algorithm-tagged per ADR-028.
///
/// ## Postconditions
/// - Phase 2 returns plaintext only after profile, algorithm, transcript,
///   expiry, signature, key derivation, and AEAD checks succeed.
///
/// ## Invariants
/// - Expiry and transcript mismatch are rejected before decryption.
pub struct OpenEnvelopeParams {
    pub recipient_classical_private_key: X25519PrivateKey,
    pub recipient_classical_public_key: X25519PublicKey,
    pub recipient_pqc_private_key: MlKemPrivateKey,
    pub sender_signing_public_key: SigningPublicKey,
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
/// - Phase 2 returns `SHA256(transcript_input)` as a `[u8; 32]`.
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
pub fn validate_envelope(envelope: &TransferEnvelope) -> Result<(), TransferError> {
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
        anonymous_recipient_public_key: None,
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
///
/// ## Postconditions
/// - Phase 2 returns a sealed envelope authenticated under the v1 transcript.
/// - Returns `Err` without partial output if any validation, key derivation,
///   signing, or encryption step fails.
///
/// ## Invariants
/// - Expiry is checked before key derivation or encryption.
/// - No plaintext secret appears in error messages or logs.
pub fn create_envelope(params: CreateEnvelopeParams) -> Result<TransferEnvelope, TransferError> {
    if let Some(expires) = params.expires_at {
        if expires <= unix_time_millis() {
            return Err(TransferError::ExpiredEnvelope);
        }
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
        anonymous_recipient_public_key: None,
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

    let mut signed_message = Vec::new();
    signed_message.extend_from_slice(TRANSFER_ENVELOPE_SIGNING_DOMAIN);
    signed_message.extend_from_slice(&transcript_hash);
    let signature = mldsa::sign(&params.sender_signing_private_key, &signed_message)
        .map_err(|_| TransferError::SigningFailed)?;

    // transfer_profile_v1.md §2 defines no cleartext signature field on
    // TransferEnvelope. Keep the public envelope layout unchanged and carry
    // algorithm-tagged signature bytes inside the AEAD payload.
    let sealed_payload = encode_signed_payload(&signature, &params.plaintext_payload)?;
    let (ciphertext, nonce) = aead::encrypt(&transfer_key, &sealed_payload, &transcript_hash)
        .map_err(|_| TransferError::EncryptionFailed)?;

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
/// - Phase 2 returns plaintext only after validation and AEAD authentication.
/// - Expired envelopes return `Err(ExpiredEnvelope)` before key derivation.
/// - Replayed envelope IDs return `Err(ReplayedEnvelopeId)` before key
///   derivation or decryption.
///
/// ## Invariants
/// - Fail closed; never returns partial plaintext on any error.
pub fn open_envelope(
    envelope: &TransferEnvelope,
    params: OpenEnvelopeParams,
    seen: &mut SeenEnvelopeIds,
) -> Result<Vec<u8>, TransferError> {
    validate_envelope(envelope)?;
    seen.check_and_insert(&envelope.envelope_id, envelope.expires_at)?;

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
    let (signature, payload) = decode_signed_payload(plaintext.as_ref())?;

    let mut signed_message = Vec::new();
    signed_message.extend_from_slice(TRANSFER_ENVELOPE_SIGNING_DOMAIN);
    signed_message.extend_from_slice(&envelope.transcript_hash);
    mldsa::verify(
        &params.sender_signing_public_key,
        &signed_message,
        &signature,
    )
    .map_err(|_| TransferError::VerificationFailed)?;

    Ok(payload.to_vec())
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

pub fn envelope_from_bytes(bytes: &[u8]) -> Result<TransferEnvelope, TransferError> {
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

fn encode_signed_payload(
    signature: &Signature,
    plaintext_payload: &[u8],
) -> Result<Vec<u8>, TransferError> {
    let signature_len =
        u32::try_from(signature.as_bytes().len()).map_err(|_| TransferError::SigningFailed)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&signature.algorithm().to_le_bytes());
    encoded.extend_from_slice(&signature_len.to_le_bytes());
    encoded.extend_from_slice(signature.as_bytes());
    encoded.extend_from_slice(plaintext_payload);
    Ok(encoded)
}

fn decode_signed_payload(bytes: &[u8]) -> Result<(Signature, &[u8]), TransferError> {
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
        .ok_or(TransferError::VerificationFailed)?;

    Ok((Signature::new(algorithm, signature_bytes), payload))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        keys::device::DEVICE_ENROLLMENT_SIGNING_DOMAIN,
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
        let original_fixture = TranscriptFixture::new();
        let original = original_fixture.params();
        let changed_profile_fixture = TranscriptFixture::new();
        let mut changed_profile = changed_profile_fixture.params();
        changed_profile.transfer_profile = TransferProfileId::test_only_unchecked(0x0002);
        let changed_envelope_fixture = TranscriptFixture {
            envelope_id: [0x99; 16],
            ..TranscriptFixture::new()
        };
        let changed_envelope = changed_envelope_fixture.params();
        let changed_expiry_fixture = TranscriptFixture::new();
        let mut changed_expiry = changed_expiry_fixture.params();
        changed_expiry.expires_at = Some(future_timestamp().checked_add(1).expect("timestamp"));

        let original_hash = compute_transcript_hash(&original);

        assert_ne!(original_hash, compute_transcript_hash(&changed_profile));
        assert_ne!(original_hash, compute_transcript_hash(&changed_envelope));
        assert_ne!(original_hash, compute_transcript_hash(&changed_expiry));
    }

    #[test]
    fn validate_envelope_rejects_expired_envelope_before_key_derivation() {
        let mut envelope = envelope_fixture();
        envelope.expires_at = Some(past_timestamp());

        assert_eq!(
            validate_envelope(&envelope),
            Err(TransferError::ExpiredEnvelope)
        );
    }

    #[test]
    fn validate_envelope_rejects_unknown_transfer_profile() {
        let mut envelope = envelope_fixture();
        envelope.transfer_profile = TransferProfileId::test_only_unchecked(0x0002);

        assert_eq!(
            validate_envelope(&envelope),
            Err(TransferError::UnknownProfile)
        );
    }

    #[test]
    fn validate_envelope_rejects_transcript_hash_mismatch() {
        let mut envelope = envelope_fixture();
        envelope.transcript_hash = [0xA5; 32];

        assert_eq!(
            validate_envelope(&envelope),
            Err(TransferError::TranscriptMismatch)
        );
    }

    #[test]
    fn transfer_signing_domain_is_distinct_from_device_domain() {
        assert_ne!(
            TRANSFER_ENVELOPE_SIGNING_DOMAIN,
            DEVICE_ENROLLMENT_SIGNING_DOMAIN
        );

        let private_key = SigningPrivateKey::new(SigningAlgorithmId::Ed25519V1, vec![0x42; 32]);
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
            recipient_classical_public_key: recipient_public,
            recipient_pqc_public_key: recipient_pqc_public,
            sender_signing_private_key,
            plaintext_payload: PAYLOAD.to_vec(),
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
                sender_signing_public_key: sender_signing_public_key.clone(),
            },
            &mut seen,
        )
        .expect("first open");
        assert_eq!(first, PAYLOAD);

        let second = open_envelope(
            &envelope,
            OpenEnvelopeParams {
                recipient_classical_private_key: Key::from_bytes(recipient_private_bytes),
                recipient_classical_public_key: Key::from_bytes(recipient_public_bytes),
                recipient_pqc_private_key: Key::from_bytes(recipient_pqc_private_bytes),
                sender_signing_public_key,
            },
            &mut seen,
        );

        assert_eq!(second, Err(TransferError::ReplayedEnvelopeId));
    }

    fn envelope_fixture() -> TransferEnvelope {
        let fixture = TranscriptFixture::new();
        let transcript_hash = compute_transcript_hash(&fixture.params());
        TransferEnvelope {
            version: 1,
            transfer_profile: TransferProfileId::v1(),
            envelope_id: fixture.envelope_id,
            sender_device_id: fixture.sender_device_id,
            recipient_device_id: Some(fixture.recipient_device_id),
            classical_ephemeral_public_key: Key::from_bytes([0x44; 32]),
            pqc_ciphertext: Key::from_bytes([0x55; 1088]),
            transcript_hash,
            encrypted_payload: vec![0x66; 16],
            nonce: [0x77; 24],
            expires_at: Some(future_timestamp()),
        }
    }

    fn create_params(expires_at: Option<Timestamp>) -> CreateEnvelopeParams {
        CreateEnvelopeParams {
            sender_device_id: [0x11; 16],
            recipient_device_id: Some([0x22; 16]),
            recipient_classical_public_key: Key::from_bytes([0x44; 32]),
            recipient_pqc_public_key: Key::from_bytes([0x55; 1184]),
            sender_signing_private_key: SigningPrivateKey::new(
                SigningAlgorithmId::Ed25519V1,
                vec![0x42; 32],
            ),
            plaintext_payload: PAYLOAD.to_vec(),
            expires_at,
        }
    }

    fn open_params() -> OpenEnvelopeParams {
        OpenEnvelopeParams {
            recipient_classical_private_key: Key::from_bytes([0x88; 32]),
            recipient_classical_public_key: Key::from_bytes([0x44; 32]),
            recipient_pqc_private_key: Key::from_bytes([0x99; 2400]),
            sender_signing_public_key: mldsa::SigningPublicKey::new(
                SigningAlgorithmId::Ed25519V1,
                vec![0xAA; 32],
            ),
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

    struct TranscriptFixture {
        sender_device_id: DeviceId,
        recipient_device_id: DeviceId,
        sender_classical_ephemeral_public_key: X25519PublicKey,
        pqc_ciphertext: MlKemCiphertext,
        envelope_id: EnvelopeId,
        expires_at: Option<Timestamp>,
    }

    impl TranscriptFixture {
        fn new() -> Self {
            Self {
                sender_device_id: [0x11; 16],
                recipient_device_id: [0x22; 16],
                sender_classical_ephemeral_public_key: Key::from_bytes([0x44; 32]),
                pqc_ciphertext: Key::from_bytes([0x55; 1088]),
                envelope_id: [0x33; 16],
                expires_at: Some(future_timestamp()),
            }
        }

        fn params(&self) -> TranscriptParams<'_> {
            TranscriptParams {
                transfer_profile: TransferProfileId::v1(),
                sender_device_id: &self.sender_device_id,
                sender_classical_ephemeral_public_key: &self.sender_classical_ephemeral_public_key,
                recipient_device_id: Some(&self.recipient_device_id),
                anonymous_recipient_public_key: None,
                pqc_ciphertext: &self.pqc_ciphertext,
                classical_algorithm_id: CLASSICAL_ALG_ID_X25519,
                pqc_algorithm_id: PQC_ALG_ID_MLKEM768,
                envelope_id: &self.envelope_id,
                expires_at: self.expires_at,
            }
        }
    }
}
