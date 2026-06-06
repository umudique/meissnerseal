//! Vault binary format contracts.

use crate::error::Result;

/// Vault file magic bytes.
pub const MAGIC: &[u8; 8] = b"ARCANUM\x01";

/// MVP-0 vault format version.
pub const FORMAT_VERSION: u16 = 1;

/// Minimum header prefix length.
pub const HEADER_MIN_LEN: usize = 26;

/// Header TLV tag: vault identifier.
pub const TAG_VAULT_ID: u16 = 0x0001;

/// Header TLV tag: creation timestamp.
pub const TAG_CREATED_AT: u16 = 0x0002;

/// Header TLV tag: KDF profile.
pub const TAG_KDF_PROFILE: u16 = 0x0003;

/// Header TLV tag: AEAD profile.
pub const TAG_AEAD_PROFILE: u16 = 0x0004;

/// Header TLV tag: PQC profile.
pub const TAG_PQC_PROFILE: u16 = 0x0005;

/// Header TLV tag: schema profile.
pub const TAG_SCHEMA_PROFILE: u16 = 0x0006;

/// Header TLV tag: header nonce.
pub const TAG_HEADER_NONCE: u16 = 0x0007;

/// Parsed vault header.
pub struct VaultHeader {
    /// 128-bit vault identifier.
    pub vault_id: [u8; 16],

    /// Creation timestamp in Unix milliseconds.
    pub created_at: u64,

    /// Vault format version.
    pub format_version: u16,

    /// Schema profile identifier.
    pub schema_profile: u16,

    /// AEAD profile identifier.
    pub aead_profile: u16,

    /// KDF profile identifier.
    pub kdf_profile: u16,

    /// PQC profile identifier.
    pub pqc_profile: u16,

    /// 24-byte vault header nonce.
    pub header_nonce: [u8; 24],
}

/// Parsed record table entry.
pub struct RecordTableEntry {
    /// 128-bit record identifier.
    pub record_id: [u8; 16],

    /// Record kind enum value.
    pub record_kind: u16,

    /// Offset of the record frame in the vault file.
    pub frame_offset: u64,

    /// Declared record frame length.
    pub frame_len: u32,
}

/// Parsed encrypted record frame.
pub struct RecordFrame {
    /// Record frame version.
    pub frame_version: u16,

    /// 128-bit record identifier.
    pub record_id: [u8; 16],

    /// AEAD nonce bytes.
    pub nonce: [u8; 24],

    /// Declared ciphertext length.
    pub ciphertext_len: u32,

    /// Ciphertext bytes including authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Parse vault header from bytes.
///
/// # Contract
/// ## Preconditions
/// - `bytes` is a complete vault file byte slice.
/// ## Postconditions
/// - On success, returns a parsed `VaultHeader`.
/// - Rejects: wrong magic bytes, unknown critical TLV tags, truncated header,
///   trailing garbage.
/// ## Invariants
/// - Never returns partial output on malformed input.
/// - Does not perform cryptographic operations directly.
#[allow(clippy::todo)]
pub fn parse_header(_bytes: &[u8]) -> Result<VaultHeader> {
    todo!()
}

/// Parse the record table from bytes at the given offset.
///
/// # Contract
/// ## Preconditions
/// - `bytes` is a complete vault file byte slice.
/// - `offset` and `len` are within bounds of `bytes`.
/// ## Postconditions
/// - Returns all record table entries or `Err`.
/// - Rejects truncated table.
/// ## Invariants
/// - Never returns partial output on malformed input.
/// - Does not perform cryptographic operations directly.
#[allow(clippy::todo)]
pub fn parse_record_table(
    _bytes: &[u8],
    _offset: usize,
    _len: usize,
) -> Result<Vec<RecordTableEntry>> {
    todo!()
}

/// Parse a record frame from bytes.
///
/// # Contract
/// ## Preconditions
/// - `bytes` points to the start of a record frame.
/// - `frame_len` is the declared length from the record table.
/// ## Postconditions
/// - Returns the parsed frame or `Err`.
/// - Rejects if `ciphertext_len` exceeds frame boundary.
/// ## Invariants
/// - Never returns partial output on malformed input.
/// - Does not perform cryptographic operations directly.
#[allow(clippy::todo)]
pub fn parse_record_frame(_bytes: &[u8], _frame_len: u32) -> Result<RecordFrame> {
    todo!()
}

/// Build canonical AAD for a vault record.
///
/// # Contract
/// ## Preconditions
/// - All parameters match the vault header and record being encrypted.
/// ## Postconditions
/// - Returns exactly 74 bytes.
/// - Output is deterministic for the same inputs.
/// ## Invariants
/// - Does not perform cryptographic operations directly.
#[allow(clippy::todo, clippy::too_many_arguments)]
pub fn build_aad(
    _vault_id: &[u8; 16],
    _format_version: u16,
    _schema_profile: u16,
    _aead_profile: u16,
    _kdf_profile: u16,
    _pqc_profile: u16,
    _record_id: &[u8; 16],
    _revision_id: &[u8; 16],
    _record_kind: u16,
) -> [u8; 74] {
    todo!()
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn verify_build_aad_length() {
        let vault_id = kani::any::<[u8; 16]>();
        let record_id = kani::any::<[u8; 16]>();
        let revision_id = kani::any::<[u8; 16]>();
        let aad = build_aad(
            &vault_id,
            kani::any::<u16>(),
            kani::any::<u16>(),
            kani::any::<u16>(),
            kani::any::<u16>(),
            kani::any::<u16>(),
            &record_id,
            &revision_id,
            kani::any::<u16>(),
        );

        kani::assert(aad.len() == 74, "AAD must always be 74 bytes");
    }

    #[kani::proof]
    fn verify_parse_header_rejects_short_input() {
        let len = kani::any::<u8>() as usize % HEADER_MIN_LEN;
        let bytes = vec![0u8; len];
        let result = parse_header(&bytes);

        kani::assert(result.is_err(), "short input must be rejected");
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    const VAULT_ID: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    const RECORD_ID: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];
    const REVISION_ID: [u8; 16] = [
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
        0xbf,
    ];

    #[test]
    fn test_magic_bytes_constant() {
        assert_eq!(MAGIC, b"ARCANUM\x01");
    }

    #[test]
    fn test_build_aad_length() {
        let aad = build_aad(&VAULT_ID, 1, 1, 1, 1, 0, &RECORD_ID, &REVISION_ID, 1);

        assert_eq!(aad.len(), 74);
    }

    #[test]
    fn test_parse_header_rejects_wrong_magic() {
        assert!(parse_header(&[0u8; 64]).is_err());
    }

    #[test]
    fn test_parse_record_frame_rejects_truncated() {
        assert!(parse_record_frame(&[], 100).is_err());
    }
}
