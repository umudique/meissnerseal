// SPDX-License-Identifier: Apache-2.0
//! DEVICE-2 out-of-band pairing payload and session contracts.

use crate::keys::device::{DeviceId, DeviceIdentity, DeviceTrustState};
use meissnerseal_pqc::mldsa::{self, Signature, SigningPrivateKey, SigningPublicKey};

/// DEVICE-2 pairing payload protocol version.
pub const PAIRING_PROTOCOL_VERSION_V1: u16 = 0x0001;
pub const DEVICE_PAIRING_SIGNING_DOMAIN: &[u8] = b"meissnerseal.device.pairing.v1\x00";

/// SHA-256 public key fingerprint length.
pub const PAIRING_FINGERPRINT_LEN: usize = 32;

/// Random pairing nonce length in bytes.
pub const PAIRING_NONCE_LEN: usize = 32;

/// Bilateral pairing commitment length in bytes.
pub const PAIRING_COMMIT_LEN: usize = 32;

/// Short authentication string length in RFC 4648 base32 characters.
pub const PAIRING_SAS_LEN: usize = 7;

/// Deprecated: use `PAIRING_SAS_LEN`.
#[deprecated(since = "0.1.0", note = "use PAIRING_SAS_LEN instead")]
pub const PAIRING_SAS_HEX_LEN: usize = PAIRING_SAS_LEN;

/// SHA-256 public key fingerprint.
pub type PublicKeyFingerprint = [u8; PAIRING_FINGERPRINT_LEN];

/// Random 256-bit pairing nonce.
pub type PairingNonce = [u8; PAIRING_NONCE_LEN];

/// Six-character out-of-band short authentication string.
pub type ShortAuthenticationString = String;

/// Pairing nonce commitment exchanged before nonce reveal.
///
/// # Contract
///
/// ## Preconditions
/// - `commit` is the 32-byte output of the pairing commitment KDF for a valid
///   pairing payload.
///
/// ## Postconditions
/// - Carries exactly one fixed-length commitment value for the commit exchange.
///
/// ## Invariants
/// - Contains only public commitment material and no secret bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingCommit {
    pub commit: [u8; PAIRING_COMMIT_LEN],
}

/// QR/manual pairing payload exchanged over an out-of-band channel.
///
/// # Contract
///
/// ## Preconditions
/// - `protocol_version` must be `PAIRING_PROTOCOL_VERSION_V1`.
/// - `device_id` must be the 128-bit device identifier from `DeviceIdentity`.
/// - Fingerprints must be full 32-byte SHA-256 digests of the raw public key
///   bytes named by `transfer_profile_v1.md §6`.
/// - `pairing_nonce` must be a random 256-bit nonzero value.
///
/// ## Postconditions
/// - `validate_pairing_payload()` rejects unknown versions and all-zero
///   nonces.
///
/// ## Invariants
/// - Contains only public metadata, public key fingerprints, capabilities, and
///   a non-secret nonce; deriving `Debug` is allowed.
/// - Does not contain raw public keys or private key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingPayload {
    pub protocol_version: u16,
    pub device_id: DeviceId,
    pub display_name: String,
    pub classical_public_key_fingerprint: PublicKeyFingerprint,
    pub pqc_public_key_fingerprint: PublicKeyFingerprint,
    pub signing_public_key_fingerprint: PublicKeyFingerprint,
    pub capabilities: u32,
    pub pairing_nonce: PairingNonce,
}

/// Pairing transcript authenticated by DEVICE-1 enrollment signing.
///
/// # Contract
///
/// ## Preconditions
/// - `payload` must pass `validate_pairing_payload()`.
/// - `transcript_hash` must be SHA-256 over the canonical pairing transcript.
///
/// ## Postconditions
/// - Phase 2 must sign the transcript using `sign_enrollment_message()` and
///   the existing DEVICE-1 enrollment domain prefix.
///
/// ## Invariants
/// - No separate pairing signing domain is introduced in Phase 1.
/// - The transcript binds the full payload, including capabilities and nonce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingTranscript {
    pub payload: PairingPayload,
    pub transcript_hash: [u8; 32],
}

/// Local pairing state for an out-of-band QR/manual exchange.
///
/// # Contract
///
/// ## Preconditions
/// - Sessions are created only from validated local and remote pairing data.
/// - The OOB channel is user-mediated; this type does not represent network
///   transport state.
///
/// ## Postconditions
/// - Phase 2 must transition trust state only through
///   `validate_trust_transition()`.
///
/// ## Invariants
/// - Holds no `DeviceKeypair`, signing private key, plaintext secret, or
///   transport handle.
/// - `Debug` output contains only public identifiers and non-secret SAS text.
#[derive(Debug, Eq, PartialEq)]
pub struct PairingSession {
    pub local_device_id: DeviceId,
    pub remote_device_id: DeviceId,
    pub sas: ShortAuthenticationString,
    pub state: DeviceTrustState,
}

/// DEVICE-2 pairing errors.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum PairingError {
    #[error("pairing implementation unavailable")]
    Unimplemented,
    #[error("pairing payload uses an unknown protocol version")]
    UnknownProtocolVersion,
    #[error("pairing identity requires a signing public key")]
    MissingSigningPublicKey,
    #[error("device display name must not be empty")]
    EmptyDisplayName,
    #[error("pairing nonce must be nonzero")]
    ZeroPairingNonce,
    #[error("pairing nonce generation failed")]
    NonceGenerationFailed,
    #[error("invalid device trust state transition")]
    InvalidTrustTransition,
    #[error("pairing commitment does not match revealed nonce")]
    CommitMismatch,
}

pub type Result<T> = core::result::Result<T, PairingError>;

/// Build a QR/manual out-of-band pairing payload from a device identity.
///
/// # Contract
///
/// ## Preconditions
/// - `identity.signing_public_key` must be `Some`; identities without signing
///   keys cannot be paired or approved.
/// - `identity` public key fields must be the public keys generated by
///   DEVICE-1.
/// - `capabilities` is the v1 u32 capability bitmask.
///
/// ## Postconditions
/// - On success, returns a payload with protocol version v1, full 32-byte
///   SHA-256 public key fingerprints, the provided capabilities bitmask, and a
///   fresh nonzero 256-bit pairing nonce.
/// - On failure, returns `Err` without producing a partial payload.
///
/// ## Invariants
/// - Hashing must use `meissnerseal_crypto::hash::sha256_bytes`.
/// - Nonce generation must use `meissnerseal_crypto::rng::random_bytes`.
/// - Core must not call PQC or primitive crypto backends directly.
pub fn build_pairing_payload(
    identity: &DeviceIdentity,
    capabilities: u32,
) -> Result<PairingPayload> {
    let pairing_nonce = generate_pairing_nonce()?;
    build_pairing_payload_with_nonce(identity, capabilities, pairing_nonce)
}

/// Build a pairing payload with an explicit nonce.
///
/// # Contract
///
/// ## Preconditions
/// - `identity.signing_public_key` must be `Some`; identities without signing
///   keys cannot be paired or approved.
/// - `identity.display_name` must be non-empty.
/// - `pairing_nonce` must be a nonzero 32-byte value generated for this
///   pairing exchange.
///
/// ## Postconditions
/// - Returns a v1 pairing payload containing the provided nonce and the
///   canonical public-key fingerprints for `identity`.
/// - Returns `Err` without producing a partial payload when validation fails.
///
/// ## Invariants
/// - Hashing uses `meissnerseal_crypto::hash::sha256_bytes`.
/// - Core does not implement cryptographic primitives directly.
pub fn build_pairing_payload_with_nonce(
    identity: &DeviceIdentity,
    capabilities: u32,
    pairing_nonce: PairingNonce,
) -> Result<PairingPayload> {
    let signing_public_key = identity
        .signing_public_key
        .as_ref()
        .ok_or(PairingError::MissingSigningPublicKey)?;
    if identity.display_name.is_empty() {
        return Err(PairingError::EmptyDisplayName);
    }
    if pairing_nonce.iter().all(|byte| *byte == 0) {
        return Err(PairingError::ZeroPairingNonce);
    }
    let classical_public_key_fingerprint =
        meissnerseal_crypto::hash::sha256_bytes(identity.classical_public_key.as_slice());
    let pqc_public_key_fingerprint =
        meissnerseal_crypto::hash::sha256_bytes(identity.pqc_public_key.as_slice());
    let signing_public_key_fingerprint =
        meissnerseal_crypto::hash::sha256_bytes(signing_public_key.as_bytes());

    Ok(PairingPayload {
        protocol_version: PAIRING_PROTOCOL_VERSION_V1,
        device_id: identity.device_id,
        display_name: identity.display_name.clone(),
        classical_public_key_fingerprint,
        pqc_public_key_fingerprint,
        signing_public_key_fingerprint,
        capabilities,
        pairing_nonce,
    })
}

/// Validate a received QR/manual out-of-band pairing payload.
///
/// # Contract
///
/// ## Preconditions
/// - `payload` is untrusted data received through a QR/manual OOB channel.
///
/// ## Postconditions
/// - Returns `Err(UnknownProtocolVersion)` for every version other than v1.
/// - Returns `Err(ZeroPairingNonce)` when `pairing_nonce` is all zeros.
/// - Returns `Ok(())` only after all structural checks pass.
///
/// ## Invariants
/// - Validation fails closed and returns no partial trust decision.
/// - This function performs no key derivation and no network access.
pub fn validate_pairing_payload(payload: &PairingPayload) -> Result<()> {
    if payload.protocol_version != PAIRING_PROTOCOL_VERSION_V1 {
        return Err(PairingError::UnknownProtocolVersion);
    }
    if payload.pairing_nonce.iter().all(|byte| *byte == 0) {
        return Err(PairingError::ZeroPairingNonce);
    }
    if payload.display_name.is_empty() {
        return Err(PairingError::EmptyDisplayName);
    }

    Ok(())
}

/// Compute the pre-reveal pairing commitment for a payload.
///
/// # Contract
///
/// ## Preconditions
/// - `payload` must be structurally valid per `validate_pairing_payload()`.
///
/// ## Postconditions
/// - Returns the 32-byte commitment bound to `payload.pairing_nonce` and the
///   canonical identity bytes for `payload`.
/// - Returns `Err` if `payload` is invalid.
///
/// ## Invariants
/// - Commitment derivation calls `meissnerseal_crypto::hkdf::sas_commit`.
/// - This function performs no network or filesystem I/O.
pub fn compute_pairing_commit(payload: &PairingPayload) -> Result<PairingCommit> {
    validate_pairing_payload(payload)?;
    let identity_bytes = pairing_identity_bytes(payload)?;
    Ok(PairingCommit {
        commit: meissnerseal_crypto::hkdf::sas_commit(&payload.pairing_nonce, &identity_bytes),
    })
}

/// Verify that a revealed payload matches a prior commitment.
///
/// # Contract
///
/// ## Preconditions
/// - `commit` is the peer commitment received before nonce reveal.
/// - `payload` is the peer payload reconstructed with the revealed nonce.
///
/// ## Postconditions
/// - Returns `Ok(())` only when the commitment recomputes exactly.
/// - Returns `Err(CommitMismatch)` on any mismatch.
///
/// ## Invariants
/// - Verification fails closed and performs no partial trust update.
pub fn verify_pairing_commit(commit: &PairingCommit, payload: &PairingPayload) -> Result<()> {
    let expected = compute_pairing_commit(payload)?;
    if expected != *commit {
        return Err(PairingError::CommitMismatch);
    }
    Ok(())
}

/// Compute the DEVICE-2 pairing transcript hash.
///
/// # Contract
///
/// ## Preconditions
/// - `payload` must be structurally valid per `validate_pairing_payload()`.
///
/// ## Postconditions
/// - Returns the SHA-256 hash of the canonical v1 pairing transcript bytes.
/// - Returns `Err` if the payload is invalid.
///
/// ## Invariants
/// - Hashing must use `meissnerseal_crypto::hash::sha256_bytes`.
/// - The transcript must bind protocol version, device ID, display name,
///   all public key fingerprints, capabilities, and pairing nonce.
pub fn compute_pairing_transcript(payload: &PairingPayload) -> Result<PairingTranscript> {
    validate_pairing_payload(payload)?;
    let mut transcript = pairing_identity_bytes(payload)?;
    transcript.extend_from_slice(&payload.pairing_nonce);

    Ok(PairingTranscript {
        payload: payload.clone(),
        transcript_hash: meissnerseal_crypto::hash::sha256_bytes(&transcript),
    })
}

/// Derive the bilateral short authentication string.
///
/// # Contract
///
/// ## Preconditions
/// - `nonce_self` and `nonce_peer` are the revealed local and remote nonces for
///   the same pairing exchange.
/// - `payload_self` and `payload_peer` are the validated local and remote
///   payloads for the same pairing exchange.
///
/// ## Postconditions
/// - Returns a 7-character RFC 4648 base32 SAS.
/// - Device-ID canonical ordering makes the result independent of caller role.
///
/// ## Invariants
/// - Derivation calls `meissnerseal_crypto::hkdf::sas_derive`.
/// - The SAS is display-only OOB verification data, not a secret.
pub fn derive_bilateral_sas(
    nonce_self: &PairingNonce,
    nonce_peer: &PairingNonce,
    payload_self: &PairingPayload,
    payload_peer: &PairingPayload,
) -> Result<ShortAuthenticationString> {
    validate_pairing_payload(payload_self)?;
    validate_pairing_payload(payload_peer)?;

    let self_identity = pairing_identity_bytes(payload_self)?;
    let peer_identity = pairing_identity_bytes(payload_peer)?;
    let sas_bytes = if payload_self.device_id <= payload_peer.device_id {
        meissnerseal_crypto::hkdf::sas_derive(
            nonce_self,
            nonce_peer,
            &self_identity,
            &peer_identity,
        )
    } else {
        meissnerseal_crypto::hkdf::sas_derive(
            nonce_peer,
            nonce_self,
            &peer_identity,
            &self_identity,
        )
    };

    Ok(sas_base32(sas_bytes))
}

/// Validate a DEVICE-2 trust-state transition.
///
/// # Contract
///
/// ## Preconditions
/// - `from` is the currently persisted trust state.
/// - `to` is the requested next trust state for the same device.
///
/// ## Postconditions
/// - Allows `Untrusted -> PendingInbound`.
/// - Allows `Untrusted -> PendingOutbound`.
/// - Allows pending states to move to `Verified`.
/// Deprecated: replaced by `derive_bilateral_sas`.
///
/// The old unilateral SAS scheme is insecure against SAS substitution attacks.
/// This stub is retained for API compatibility only and always returns `Err`.
#[doc(hidden)]
#[deprecated(since = "0.1.0", note = "use derive_bilateral_sas instead")]
pub fn derive_short_authentication_string(
    _pairing_nonce: &PairingNonce,
    _transcript_hash: &[u8; 32],
) -> core::result::Result<ShortAuthenticationString, crate::error::CoreError> {
    Err(crate::error::CoreError::Format(
        "derive_short_authentication_string is superseded by derive_bilateral_sas".into(),
    ))
}

/// - Allows `Verified -> Approved`.
/// - Returns `Err(InvalidTrustTransition)` for skipped or backward states.
///
/// ## Invariants
/// - Invalid transitions are never silently accepted.
/// - `Revoked` and `Expired` remain terminal states.
pub fn validate_trust_transition(from: DeviceTrustState, to: DeviceTrustState) -> Result<()> {
    match (from, to) {
        (DeviceTrustState::Untrusted, DeviceTrustState::PendingInbound)
        | (DeviceTrustState::Untrusted, DeviceTrustState::PendingOutbound)
        | (DeviceTrustState::PendingInbound, DeviceTrustState::Verified)
        | (DeviceTrustState::PendingOutbound, DeviceTrustState::Verified)
        | (DeviceTrustState::Verified, DeviceTrustState::Approved)
        | (DeviceTrustState::Untrusted, DeviceTrustState::Revoked)
        | (DeviceTrustState::PendingInbound, DeviceTrustState::Revoked)
        | (DeviceTrustState::PendingOutbound, DeviceTrustState::Revoked)
        | (DeviceTrustState::Verified, DeviceTrustState::Revoked)
        | (DeviceTrustState::Approved, DeviceTrustState::Revoked)
        | (DeviceTrustState::Revoked, DeviceTrustState::Revoked)
        | (DeviceTrustState::Untrusted, DeviceTrustState::Expired)
        | (DeviceTrustState::PendingInbound, DeviceTrustState::Expired)
        | (DeviceTrustState::PendingOutbound, DeviceTrustState::Expired)
        | (DeviceTrustState::Verified, DeviceTrustState::Expired)
        | (DeviceTrustState::Approved, DeviceTrustState::Expired)
        | (DeviceTrustState::Expired, DeviceTrustState::Expired) => Ok(()),
        _ => Err(PairingError::InvalidTrustTransition),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn sign_pairing_message(key: &SigningPrivateKey, msg: &[u8]) -> Result<Signature> {
    mldsa::sign_with_domain(key, DEVICE_PAIRING_SIGNING_DOMAIN, msg)
        .map_err(|_| PairingError::Unimplemented)
}

#[cfg_attr(not(test), allow(dead_code))]
fn verify_pairing_message(key: &SigningPublicKey, msg: &[u8], sig: &Signature) -> bool {
    mldsa::verify_with_domain(key, DEVICE_PAIRING_SIGNING_DOMAIN, msg, sig).is_ok()
}

/// # Contract
///
/// ## Preconditions
/// - `payload` must describe a pairing identity with protocol version,
///   fingerprints, and capabilities already validated structurally.
///
/// ## Postconditions
/// - Returns the canonical identity encoding used by pairing commit and SAS
///   derivation, excluding `pairing_nonce`.
///
/// ## Invariants
/// - Encoding order is fixed and deterministic across callers.
fn pairing_identity_bytes(payload: &PairingPayload) -> Result<Vec<u8>> {
    let display_name_len =
        u32::try_from(payload.display_name.len()).map_err(|_| PairingError::EmptyDisplayName)?;
    let mut identity = Vec::new();
    identity.extend_from_slice(&payload.protocol_version.to_le_bytes());
    identity.extend_from_slice(&payload.device_id);
    identity.extend_from_slice(&display_name_len.to_le_bytes());
    identity.extend_from_slice(payload.display_name.as_bytes());
    identity.extend_from_slice(&payload.classical_public_key_fingerprint);
    identity.extend_from_slice(&payload.pqc_public_key_fingerprint);
    identity.extend_from_slice(&payload.signing_public_key_fingerprint);
    identity.extend_from_slice(&payload.capabilities.to_le_bytes());
    Ok(identity)
}

fn sas_base32(bytes: [u8; 4]) -> String {
    const RFC4648_BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let quintets = [
        bytes[0] >> 3,
        ((bytes[0] & 0x07) << 2) | (bytes[1] >> 6),
        (bytes[1] >> 1) & 0x1f,
        ((bytes[1] & 0x01) << 4) | (bytes[2] >> 4),
        ((bytes[2] & 0x0f) << 1) | (bytes[3] >> 7),
        (bytes[3] >> 2) & 0x1f,
        (bytes[3] & 0x03) << 3,
    ];
    let mut out = String::with_capacity(PAIRING_SAS_LEN);
    for quintet in quintets {
        if let Some(symbol) = RFC4648_BASE32.get(usize::from(quintet)) {
            out.push(char::from(*symbol));
        }
    }
    out
}

fn generate_pairing_nonce() -> Result<PairingNonce> {
    let first = random_nonce_candidate()?;
    if first.iter().any(|byte| *byte != 0) {
        return Ok(first);
    }

    let second = random_nonce_candidate()?;
    if second.iter().any(|byte| *byte != 0) {
        return Ok(second);
    }

    Err(PairingError::NonceGenerationFailed)
}

fn random_nonce_candidate() -> Result<PairingNonce> {
    meissnerseal_crypto::rng::random_bytes(PAIRING_NONCE_LEN)
        .try_into()
        .map_err(|_| PairingError::NonceGenerationFailed)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::keys::device::DEVICE_ENROLLMENT_SIGNING_DOMAIN;
    use meissnerseal_crypto::types::Key;
    use meissnerseal_pqc::mldsa::{SigningAlgorithmId, SigningPublicKey};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn distinct_device_identities_produce_distinct_pairing_payloads(
            first_device_id in proptest::array::uniform16(0u8..),
            second_device_id in proptest::array::uniform16(0u8..),
            first_classical in proptest::array::uniform32(0u8..),
            second_classical in proptest::array::uniform32(0u8..),
            first_pqc in proptest::array::uniform::<_, 1184>(0u8..),
            second_pqc in proptest::array::uniform::<_, 1184>(0u8..),
            first_signing in proptest::array::uniform32(0u8..),
            second_signing in proptest::array::uniform32(0u8..),
        ) {
            let first = identity(
                first_device_id,
                "first",
                first_classical,
                first_pqc,
                Some(first_signing),
                DeviceTrustState::Untrusted,
            );
            let second = identity(
                second_device_id,
                "second",
                second_classical,
                second_pqc,
                Some(second_signing),
                DeviceTrustState::Untrusted,
            );
            prop_assume!(identities_differ(&first, &second));

            let first_payload = build_pairing_payload(&first, 0x01).expect("payload");
            let second_payload = build_pairing_payload(&second, 0x01).expect("payload");

            prop_assert_ne!(first_payload, second_payload);
        }
    }

    #[test]
    fn build_pairing_payload_without_signing_key_returns_err() {
        let identity = identity(
            [0x11; 16],
            "missing-signing",
            [0x22; 32],
            [0x33; 1184],
            None,
            DeviceTrustState::Untrusted,
        );

        assert_eq!(
            build_pairing_payload(&identity, 0x01),
            Err(PairingError::MissingSigningPublicKey)
        );
    }

    #[test]
    fn build_pairing_payload_with_empty_display_name_returns_err() {
        let identity = identity(
            [0x11; 16],
            "",
            [0x22; 32],
            [0x33; 1184],
            Some([0x44; 32]),
            DeviceTrustState::Untrusted,
        );

        assert_eq!(
            build_pairing_payload(&identity, 0x01),
            Err(PairingError::EmptyDisplayName)
        );
    }

    #[test]
    fn validate_pairing_payload_rejects_unknown_protocol_version() {
        let mut payload = payload_fixture();
        payload.protocol_version = 0xffff;

        assert_eq!(
            validate_pairing_payload(&payload),
            Err(PairingError::UnknownProtocolVersion)
        );
    }

    #[test]
    fn validate_pairing_payload_rejects_zero_pairing_nonce() {
        let mut payload = payload_fixture();
        payload.pairing_nonce = [0u8; PAIRING_NONCE_LEN];

        assert_eq!(
            validate_pairing_payload(&payload),
            Err(PairingError::ZeroPairingNonce)
        );
    }

    #[test]
    fn compute_pairing_transcript_matches_fixed_kat() {
        let transcript = compute_pairing_transcript(&payload_fixture()).expect("transcript");

        assert_eq!(
            transcript.transcript_hash,
            [
                0x88, 0xb8, 0x48, 0xe6, 0x85, 0xc9, 0x0e, 0xd5, 0xd7, 0x6b, 0xce, 0x97, 0x71, 0x31,
                0x9d, 0xa7, 0xb9, 0x5e, 0x9a, 0x3d, 0xfe, 0xdc, 0x01, 0x61, 0xff, 0x6a, 0xeb, 0x50,
                0x76, 0x34, 0x92, 0x51
            ]
        );
    }

    #[test]
    fn compute_pairing_commit_changes_when_nonce_changes() {
        let self_identity = identity(
            [0x11; 16],
            "self",
            [0x22; 32],
            [0x33; 1184],
            Some([0x44; 32]),
            DeviceTrustState::Untrusted,
        );
        let first_payload =
            build_pairing_payload_with_nonce(&self_identity, 0x01, [0x55; PAIRING_NONCE_LEN])
                .expect("first payload");
        let second_payload =
            build_pairing_payload_with_nonce(&self_identity, 0x01, [0x66; PAIRING_NONCE_LEN])
                .expect("second payload");

        let first_commit = compute_pairing_commit(&first_payload).expect("first commit");
        let second_commit = compute_pairing_commit(&second_payload).expect("second commit");

        assert_ne!(first_commit.commit, second_commit.commit);
    }

    #[test]
    fn verify_pairing_commit_rejects_mismatch() {
        let payload = payload_fixture();
        let commit = PairingCommit {
            commit: [0xAA; PAIRING_COMMIT_LEN],
        };

        assert_eq!(
            verify_pairing_commit(&commit, &payload),
            Err(PairingError::CommitMismatch)
        );
    }

    #[test]
    fn derive_bilateral_sas_is_order_independent() {
        let first_payload = payload_fixture();
        let mut second_payload = payload_fixture();
        second_payload.device_id = [0x99; 16];
        second_payload.display_name = "second-device".to_owned();
        second_payload.pairing_nonce = [0x77; PAIRING_NONCE_LEN];

        let first = derive_bilateral_sas(
            &first_payload.pairing_nonce,
            &second_payload.pairing_nonce,
            &first_payload,
            &second_payload,
        )
        .expect("forward sas");
        let second = derive_bilateral_sas(
            &second_payload.pairing_nonce,
            &first_payload.pairing_nonce,
            &second_payload,
            &first_payload,
        )
        .expect("reverse sas");

        assert_eq!(first, second);
        assert_eq!(first.len(), PAIRING_SAS_LEN);
    }

    #[test]
    fn sas_base32_matches_known_answers() {
        assert_eq!(sas_base32([0x00, 0x00, 0x00, 0x00]), "AAAAAAA");
        assert_eq!(sas_base32([0xff, 0xff, 0xff, 0xff]), "777777Y");
    }

    #[test]
    fn untrusted_to_pending_inbound_is_valid() {
        assert_eq!(
            validate_trust_transition(
                DeviceTrustState::Untrusted,
                DeviceTrustState::PendingInbound
            ),
            Ok(())
        );
    }

    #[test]
    fn verified_to_untrusted_is_invalid() {
        assert_eq!(
            validate_trust_transition(DeviceTrustState::Verified, DeviceTrustState::Untrusted),
            Err(PairingError::InvalidTrustTransition)
        );
    }

    #[test]
    fn pending_inbound_to_approved_skips_verified_and_is_invalid() {
        assert_eq!(
            validate_trust_transition(DeviceTrustState::PendingInbound, DeviceTrustState::Approved),
            Err(PairingError::InvalidTrustTransition)
        );
    }

    #[test]
    fn any_state_to_revoked_is_valid() {
        for from in [
            DeviceTrustState::Untrusted,
            DeviceTrustState::Verified,
            DeviceTrustState::Approved,
        ] {
            assert_eq!(
                validate_trust_transition(from, DeviceTrustState::Revoked),
                Ok(())
            );
        }
    }

    #[test]
    fn pending_states_to_revoked_are_valid() {
        assert_eq!(
            validate_trust_transition(DeviceTrustState::PendingInbound, DeviceTrustState::Revoked),
            Ok(())
        );
        assert_eq!(
            validate_trust_transition(DeviceTrustState::PendingOutbound, DeviceTrustState::Revoked),
            Ok(())
        );
    }

    #[test]
    fn expired_to_revoked_is_invalid() {
        assert_eq!(
            validate_trust_transition(DeviceTrustState::Expired, DeviceTrustState::Revoked),
            Err(PairingError::InvalidTrustTransition)
        );
    }

    #[test]
    fn revoked_to_expired_is_invalid() {
        assert_eq!(
            validate_trust_transition(DeviceTrustState::Revoked, DeviceTrustState::Expired),
            Err(PairingError::InvalidTrustTransition)
        );
    }

    #[test]
    fn pairing_verify_rejects_enrollment_domain_signature() {
        let (public_key, private_key) = mldsa::ed25519_keypair();
        let message = b"pairing transcript";
        let signature =
            mldsa::sign_with_domain(&private_key, DEVICE_ENROLLMENT_SIGNING_DOMAIN, message)
                .expect("enrollment-domain signature");

        assert!(!verify_pairing_message(&public_key, message, &signature));
        let pairing_signature =
            sign_pairing_message(&private_key, message).expect("pairing-domain signature");
        assert!(verify_pairing_message(
            &public_key,
            message,
            &pairing_signature
        ));
    }

    fn payload_fixture() -> PairingPayload {
        PairingPayload {
            protocol_version: PAIRING_PROTOCOL_VERSION_V1,
            device_id: [0x11; 16],
            display_name: "phase1-device".to_owned(),
            classical_public_key_fingerprint: [0x22; PAIRING_FINGERPRINT_LEN],
            pqc_public_key_fingerprint: [0x33; PAIRING_FINGERPRINT_LEN],
            signing_public_key_fingerprint: [0x44; PAIRING_FINGERPRINT_LEN],
            capabilities: 0x01,
            pairing_nonce: [0x55; PAIRING_NONCE_LEN],
        }
    }

    fn identity(
        device_id: DeviceId,
        display_name: &str,
        classical_public_key: [u8; 32],
        pqc_public_key: [u8; 1184],
        signing_public_key: Option<[u8; 32]>,
        trust_state: DeviceTrustState,
    ) -> DeviceIdentity {
        DeviceIdentity {
            device_id,
            display_name: display_name.to_owned(),
            classical_public_key: Key::from_bytes(classical_public_key),
            pqc_public_key: Key::from_bytes(pqc_public_key),
            signing_public_key: signing_public_key
                .map(|bytes| SigningPublicKey::new(SigningAlgorithmId::Ed25519V1, bytes.to_vec())),
            created_at: 1,
            trust_state,
        }
    }

    fn identities_differ(first: &DeviceIdentity, second: &DeviceIdentity) -> bool {
        first.device_id != second.device_id
            || first.display_name != second.display_name
            || first.classical_public_key.as_slice() != second.classical_public_key.as_slice()
            || first.pqc_public_key.as_slice() != second.pqc_public_key.as_slice()
            || first
                .signing_public_key
                .as_ref()
                .map(SigningPublicKey::as_bytes)
                != second
                    .signing_public_key
                    .as_ref()
                    .map(SigningPublicKey::as_bytes)
    }
}
