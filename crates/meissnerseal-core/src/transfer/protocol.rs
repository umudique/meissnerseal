// SPDX-License-Identifier: Apache-2.0
//! Transfer profile identifiers and fail-closed transfer errors.

/// Transfer profile ID for `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1`.
///
/// `transfer_profile_v1.md` names the profile but does not assign a numeric
/// wire value; XFER-1 registers `0x0001` for the MVP v1 profile.
pub const TRANSFER_PROFILE_V1_ID: u16 = 0x0001;

/// Classical algorithm ID for X25519 in `transfer_profile_v1.md §4`.
pub const CLASSICAL_ALG_ID_X25519: u16 = 0x0001;

/// PQC algorithm ID for ML-KEM-768 in `transfer_profile_v1.md §4`.
pub const PQC_ALG_ID_MLKEM768: u16 = 0x0001;

/// 128-bit random transfer envelope identifier.
pub type EnvelopeId = [u8; 16];

/// Wire-encodable transfer profile identifier.
///
/// # Contract
///
/// ## Preconditions
/// - Wire values are encoded little-endian as `u16`.
/// - Unknown profile IDs must be rejected before key derivation or decryption.
///
/// ## Postconditions
/// - `TransferProfileId::v1()` represents
///   `TRANSFER_HYBRID_X25519_MLKEM768_SHA256_V1`.
/// - `from_u16` and `from_le_bytes` return `Err(UnknownProfile)` for every
///   value other than `TRANSFER_PROFILE_V1_ID`.
///
/// ## Invariants
/// - Callers do not infer algorithms from key lengths or ciphertext shape.
/// - Profile ID is a downgrade-critical field and must be transcript-bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferProfileId(u16);

impl TransferProfileId {
    #[must_use]
    pub const fn v1() -> Self {
        Self(TRANSFER_PROFILE_V1_ID)
    }

    #[must_use]
    pub const fn to_u16(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 2] {
        self.0.to_le_bytes()
    }

    pub fn from_le_bytes(bytes: [u8; 2]) -> Result<Self, TransferError> {
        Self::from_u16(u16::from_le_bytes(bytes))
    }

    pub fn from_u16(value: u16) -> Result<Self, TransferError> {
        if value == TRANSFER_PROFILE_V1_ID {
            Ok(Self(value))
        } else {
            Err(TransferError::UnknownProfile)
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn test_only_unchecked(value: u16) -> Self {
        Self(value)
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum TransferError {
    #[error("unknown transfer profile")]
    UnknownProfile,
    #[error("transfer envelope expired")]
    ExpiredEnvelope,
    #[error("transfer envelope id has already been accepted")]
    ReplayedEnvelopeId,
    #[error("transfer transcript hash mismatch")]
    TranscriptMismatch,
    #[error("missing PQC ciphertext")]
    MissingPqcCiphertext,
    #[error("transfer algorithm identifier mismatch")]
    AlgorithmMismatch,
    #[error("transfer key derivation failed")]
    KeyDerivationFailed,
    #[error("transfer encryption failed")]
    EncryptionFailed,
    #[error("transfer decryption failed")]
    DecryptionFailed,
    #[error("transfer signing failed")]
    SigningFailed,
    #[error("transfer signature verification failed")]
    VerificationFailed,
    #[error("invalid transfer envelope id")]
    InvalidEnvelopeId,
    #[error("transfer transcript hash helper unavailable")]
    TranscriptHashUnavailable,
    #[error("replay store file format is unknown or corrupt")]
    MalformedReplayStore,
    #[error("transfer implementation unavailable")]
    Unimplemented,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_profile_id_from_le_bytes_rejects_unknown_values() {
        assert_eq!(
            TransferProfileId::from_le_bytes([0xff, 0x7f]),
            Err(TransferError::UnknownProfile)
        );
    }

    #[test]
    fn transfer_profile_id_wire_roundtrip() {
        let profile = TransferProfileId::v1();

        assert_eq!(
            TransferProfileId::from_le_bytes(profile.to_le_bytes()),
            Ok(profile)
        );
    }
}
