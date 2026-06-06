//! HKDF-SHA256 derivation contracts.

use crate::kdf::{KdfError, Result};
use crate::types::{DerivedSubkey, HeaderNonce, HkdfPrk, Key, VaultRootKey};
use core::fmt::Write;
use sha2::{Digest, Sha256};

const ROOT_SALT_DOMAIN_V1: &[u8; 20] = b"arcanum-root-salt-v1";

/// HKDF pseudo-random key.
pub type Prk = HkdfPrk;

/// HKDF-derived subkey.
pub type SubKey = DerivedSubkey;

/// HKDF subkey purpose registry.
#[derive(Clone, Copy, Debug)]
pub enum SubkeyPurpose {
    /// Item key wrapping key, scoped to an AEAD algorithm identifier.
    ItemKeyWrappingKey,

    /// Metadata encryption key, scoped to an AEAD algorithm identifier.
    MetadataEncryptionKey,

    /// Local audit event key.
    LocalAuditEventKey,

    /// Sync envelope key.
    SyncEnvelopeKey,

    /// Device enrollment key.
    DeviceEnrollmentKey,

    /// Recovery wrapping key.
    RecoveryWrappingKey,

    /// Export bundle key.
    ExportBundleKey,
}

/// HKDF-SHA256 extract.
///
/// # Contract
/// ## Preconditions
/// - `salt` is the domain-separated salt required by the caller's derivation
///   context.
/// - `ikm` is caller-owned input keying material and is never logged, printed,
///   or written to any output.
/// ## Postconditions
/// - Returns exactly one 32-byte `Prk`.
/// - Does not expose intermediate HMAC state or partial output.
/// ## Invariants
/// - Uses no custom cryptographic primitive.
/// - All fixed-length secret output is represented by `Prk`.
/// - Secret values are not compared with `==`; constant-time comparison is used
///   wherever secret equality is required.
pub fn extract(salt: &[u8], ikm: &[u8]) -> Prk {
    let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut bytes = [0u8; Prk::LEN];
    bytes.copy_from_slice(&prk);
    Prk::from_bytes(bytes)
}

/// HKDF-SHA256 expand into a fixed-length key.
///
/// # Contract
/// ## Preconditions
/// - `prk` was produced by HKDF-SHA256 extract for the same derivation chain.
/// - `info` is deterministic ASCII domain-separation text.
/// - `N` encodes the fixed output length; callers must not request partial
///   fixed-length keys.
/// ## Postconditions
/// - On success, returns exactly one `Key<N>`.
/// - On failure, returns `Err` and exposes no partial key material.
/// ## Invariants
/// - Uses no custom cryptographic primitive.
/// - All fixed-length secret output is represented by `Key<N>`.
/// - Secret values are not logged, printed, written, or compared with `==`.
pub fn expand<const N: usize>(prk: &Prk, info: &[u8]) -> Result<Key<N>> {
    let hkdf =
        hkdf::Hkdf::<Sha256>::from_prk(prk.as_slice()).map_err(|_| KdfError::InvalidInput)?;
    let mut output = [0u8; N];
    hkdf.expand(info, &mut output)
        .map_err(|_| KdfError::InvalidInput)?;
    Ok(Key::from_bytes(output))
}

/// Derive a 32-byte subkey from a root PRK and purpose-specific HKDF info.
///
/// # Contract
/// ## Preconditions
/// - `root_prk` was derived by the root PRK derivation chain in
///   `specs/crypto/crypto_design.md` section 3.
/// - `purpose` is one of the registered `SubkeyPurpose` variants.
/// - `vault_id` is the canonical 128-bit vault UUID and is encoded in HKDF info
///   as lowercase hex with exactly 32 ASCII characters.
/// - `aead_id` is `Some(decimal)` exactly when `purpose` requires an AEAD
///   algorithm identifier; otherwise it is `None`.
/// ## Postconditions
/// - On success, returns exactly one 32-byte `SubKey`.
/// - On failure, returns `Err` and exposes no partial key material.
/// - The HKDF info string is deterministic ASCII and matches the specified
///   `arcanum:{purpose}:v1:vault:{vault_id_hex}` format, with
///   `:aead:{aead_id_decimal}` appended when required.
/// ## Invariants
/// - Uses no custom cryptographic primitive.
/// - All fixed-length secret output is represented by `SubKey`.
/// - Secret values are not logged, printed, written, or compared with `==`.
pub fn derive_subkey(
    root_prk: &Prk,
    purpose: SubkeyPurpose,
    vault_id: &[u8; 16],
    aead_id: Option<u16>,
) -> Result<SubKey> {
    let info = build_subkey_info(purpose, vault_id, aead_id)?;
    expand::<{ SubKey::LEN }>(root_prk, info.as_bytes())
}

#[allow(dead_code)]
fn derive_root_prk(
    vault_root_key: &VaultRootKey,
    vault_id: &[u8; 16],
    header_nonce: &HeaderNonce,
) -> Prk {
    let mut hasher = Sha256::new();
    hasher.update(ROOT_SALT_DOMAIN_V1);
    hasher.update(vault_id);
    hasher.update(header_nonce.as_slice());
    let root_salt = hasher.finalize();

    extract(&root_salt, vault_root_key.as_slice())
}

fn build_subkey_info(
    purpose: SubkeyPurpose,
    vault_id: &[u8; 16],
    aead_id: Option<u16>,
) -> Result<String> {
    let purpose_str = purpose.info_label();
    let mut vault_id_hex = String::new();
    for byte in vault_id {
        if write!(&mut vault_id_hex, "{byte:02x}").is_err() {
            return Err(KdfError::InvalidInput);
        }
    }

    let mut info = format!("arcanum:{purpose_str}:v1:vault:{vault_id_hex}");
    match (purpose.needs_aead(), aead_id) {
        (true, Some(id)) => {
            if write!(&mut info, ":aead:{id}").is_err() {
                return Err(KdfError::InvalidInput);
            }
            Ok(info)
        }
        (true, None) => Err(KdfError::InvalidInput),
        (false, None) => Ok(info),
        (false, Some(_)) => Err(KdfError::InvalidInput),
    }
}

impl SubkeyPurpose {
    fn info_label(self) -> &'static str {
        match self {
            Self::ItemKeyWrappingKey => "item-wrap",
            Self::MetadataEncryptionKey => "metadata",
            Self::LocalAuditEventKey => "audit",
            Self::SyncEnvelopeKey => "sync-envelope",
            Self::DeviceEnrollmentKey => "device-enroll",
            Self::RecoveryWrappingKey => "recovery-wrap",
            Self::ExportBundleKey => "export-bundle",
        }
    }

    fn needs_aead(self) -> bool {
        matches!(self, Self::ItemKeyWrappingKey | Self::MetadataEncryptionKey)
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn verify_hkdf_info_ascii() {
        let vault_id = kani::any::<[u8; 16]>();
        if let Ok(info) = build_subkey_info(SubkeyPurpose::LocalAuditEventKey, &vault_id, None) {
            kani::assert(info.is_ascii(), "HKDF info string must be valid ASCII");
        }
    }

    #[kani::proof]
    fn verify_expand_output_length() {
        let prk = Prk::from_bytes(kani::any::<[u8; 32]>());
        let info = b"arcanum:test:v1";
        if let Ok(key) = expand::<32>(&prk, info) {
            kani::assert(
                key.as_slice().len() == 32,
                "expand<32> must produce 32 bytes",
            );
        }
    }

    #[kani::proof]
    fn verify_derive_subkey_rejects_aead_mismatch() {
        let root_prk = Prk::from_bytes(kani::any::<[u8; 32]>());
        let vault_id = kani::any::<[u8; 16]>();
        // Non-AEAD purpose with Some(aead_id) must be rejected
        let result = derive_subkey(
            &root_prk,
            SubkeyPurpose::LocalAuditEventKey,
            &vault_id,
            Some(1),
        );
        kani::assert(
            result.is_err(),
            "non-AEAD purpose with aead_id must return Err",
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const VAULT_ID: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    const VAULT_ROOT_KEY: [u8; 32] = [
        0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
        0x8f, 0x90, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const HEADER_NONCE: [u8; 24] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24,
    ];
    const EXPECTED_ROOT_PRK: [u8; 32] = [
        0x24, 0x03, 0x4e, 0x17, 0x11, 0x82, 0x40, 0x32, 0x3a, 0x71, 0xf8, 0xd8, 0x80, 0xad, 0x33,
        0x56, 0xfa, 0x1b, 0xa3, 0x04, 0xea, 0x9a, 0x7a, 0x26, 0x94, 0x5e, 0x47, 0x08, 0xbe, 0xbe,
        0xc8, 0xf9,
    ];
    const EXPECTED_ITEM_KEY_WRAPPING_KEY: [u8; 32] = [
        0x39, 0xbf, 0x9e, 0x28, 0xa9, 0x03, 0x06, 0x24, 0x6f, 0x0b, 0xfc, 0x3c, 0xb8, 0x19, 0x2c,
        0xd9, 0xc3, 0x62, 0xa7, 0x08, 0x25, 0x24, 0x77, 0x39, 0x87, 0x5c, 0xf5, 0x7b, 0x54, 0x61,
        0x13, 0x89,
    ];
    const EXPECTED_METADATA_ENCRYPTION_KEY: [u8; 32] = [
        0xb6, 0xd1, 0x70, 0xe1, 0xb7, 0x44, 0x0e, 0x07, 0x9d, 0x06, 0xc0, 0x2e, 0x40, 0x08, 0x77,
        0x44, 0xb4, 0xd4, 0x5b, 0x37, 0xcc, 0x9c, 0xfe, 0xf3, 0x61, 0x31, 0xe6, 0x44, 0x52, 0xb5,
        0xea, 0x58,
    ];
    const EXPECTED_LOCAL_AUDIT_EVENT_KEY: [u8; 32] = [
        0x04, 0x18, 0xf4, 0xab, 0x3c, 0x08, 0x61, 0x8f, 0xc9, 0x3e, 0x2f, 0xd9, 0xbb, 0xd7, 0x35,
        0xda, 0x11, 0xe8, 0x3f, 0x3c, 0x5f, 0xe8, 0x01, 0x5e, 0x33, 0xd2, 0x89, 0x09, 0xc3, 0x0d,
        0x57, 0x07,
    ];
    const EXPECTED_SYNC_ENVELOPE_KEY: [u8; 32] = [
        0x10, 0xf2, 0x29, 0x77, 0xa2, 0x52, 0x3a, 0x2b, 0xe9, 0x7a, 0xa9, 0x25, 0x94, 0x5f, 0xe5,
        0x57, 0x9c, 0x26, 0x90, 0xf7, 0x43, 0x72, 0xfd, 0x0b, 0xe5, 0xcc, 0x57, 0xf9, 0xd2, 0x11,
        0xd4, 0xd7,
    ];
    const EXPECTED_DEVICE_ENROLLMENT_KEY: [u8; 32] = [
        0x68, 0xa1, 0xa9, 0xcf, 0x2c, 0x34, 0x96, 0x78, 0x0d, 0x5b, 0xa6, 0xa0, 0x39, 0xa0, 0x5a,
        0x2c, 0xdf, 0x46, 0x5b, 0x89, 0x6b, 0x7d, 0x4c, 0xd6, 0xbe, 0x85, 0xc0, 0x44, 0x99, 0x21,
        0xfb, 0xf7,
    ];
    const EXPECTED_RECOVERY_WRAPPING_KEY: [u8; 32] = [
        0xd7, 0x44, 0x69, 0x2d, 0x9a, 0x7d, 0x18, 0x6c, 0xd8, 0x41, 0x00, 0x2b, 0x86, 0xdd, 0xd5,
        0x5a, 0xa6, 0x5f, 0x52, 0x36, 0x4f, 0x2f, 0x78, 0xf4, 0x2f, 0x12, 0x45, 0x1a, 0xb1, 0x6a,
        0xb3, 0x35,
    ];
    const EXPECTED_EXPORT_BUNDLE_KEY: [u8; 32] = [
        0xc2, 0x82, 0x42, 0x5b, 0x3d, 0x6f, 0x6e, 0x7e, 0xea, 0x0f, 0x02, 0xc6, 0x3f, 0x7a, 0x93,
        0x04, 0xa4, 0x45, 0x6e, 0x47, 0x8e, 0x88, 0x1b, 0xcc, 0x9a, 0x8e, 0x1f, 0x72, 0x38, 0x4f,
        0xe0, 0xc1,
    ];

    #[test]
    fn test_root_prk_derivation() {
        let vault_root_key = VaultRootKey::from_bytes(VAULT_ROOT_KEY);
        let header_nonce = HeaderNonce::from_bytes(HEADER_NONCE);
        let root_prk = derive_root_prk(&vault_root_key, &VAULT_ID, &header_nonce);
        let expected = Prk::from_bytes(EXPECTED_ROOT_PRK);

        assert!(bool::from(root_prk.ct_eq(&expected)));
    }

    #[test]
    fn test_subkey_derivation_all() {
        let root_prk = Prk::from_bytes(EXPECTED_ROOT_PRK);

        assert_subkey(
            &root_prk,
            SubkeyPurpose::ItemKeyWrappingKey,
            Some(1),
            EXPECTED_ITEM_KEY_WRAPPING_KEY,
        );
        assert_subkey(
            &root_prk,
            SubkeyPurpose::MetadataEncryptionKey,
            Some(1),
            EXPECTED_METADATA_ENCRYPTION_KEY,
        );
        assert_subkey(
            &root_prk,
            SubkeyPurpose::LocalAuditEventKey,
            None,
            EXPECTED_LOCAL_AUDIT_EVENT_KEY,
        );
        assert_subkey(
            &root_prk,
            SubkeyPurpose::SyncEnvelopeKey,
            None,
            EXPECTED_SYNC_ENVELOPE_KEY,
        );
        assert_subkey(
            &root_prk,
            SubkeyPurpose::DeviceEnrollmentKey,
            None,
            EXPECTED_DEVICE_ENROLLMENT_KEY,
        );
        assert_subkey(
            &root_prk,
            SubkeyPurpose::RecoveryWrappingKey,
            None,
            EXPECTED_RECOVERY_WRAPPING_KEY,
        );
        assert_subkey(
            &root_prk,
            SubkeyPurpose::ExportBundleKey,
            None,
            EXPECTED_EXPORT_BUNDLE_KEY,
        );
    }

    fn assert_subkey(
        root_prk: &Prk,
        purpose: SubkeyPurpose,
        aead_id: Option<u16>,
        expected_bytes: [u8; 32],
    ) {
        let subkey = derive_subkey(root_prk, purpose, &VAULT_ID, aead_id).expect("subkey");
        let expected = SubKey::from_bytes(expected_bytes);

        assert!(bool::from(subkey.ct_eq(&expected)));
    }
}
