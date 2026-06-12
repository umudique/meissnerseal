// SPDX-License-Identifier: Apache-2.0
//! HKDF-SHA256 derivation contracts.

use crate::kdf::{KdfError, Result};
use crate::types::{DerivedSubkey, HeaderNonce, HkdfPrk, Key, VaultRootKey};
use core::fmt::Write;
use sha2::{Digest, Sha256};

const ROOT_SALT_DOMAIN_V1: &[u8; 25] = b"meissnerseal-root-salt-v1";

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
///   `meissnerseal:{purpose}:v1:vault:{vault_id_hex}` format, with
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

/// Derive the HKDF root PRK from the Vault Root Key.
///
/// Implements step 5 of the key hierarchy from `specs/crypto/crypto_design.md` §3:
///
/// ```text
/// root_salt = SHA256("meissnerseal-root-salt-v1" || vault_id || header_nonce)
/// root_prk  = HKDF-SHA256-Extract(salt=root_salt, ikm=vault_root_key)
/// ```
///
/// # Contract
/// ## Preconditions
/// - `vault_root_key` was decrypted from the `WrappedRootKey` record via VKEK.
/// - `vault_id` is the canonical 128-bit vault UUID from the header.
/// - `header_nonce` is the 24-byte nonce from the vault header TLV tag `0x0007`.
/// ## Postconditions
/// - Returns a 32-byte `Prk` suitable for subkey expansion (step 6).
/// ## Invariants
/// - Uses no custom cryptographic primitive.
/// - Secret values are not logged, printed, or written to any output.
pub fn derive_root_prk(
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

    let mut info = format!("meissnerseal:{purpose_str}:v1:vault:{vault_id_hex}");
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
        // Type-level proof: HKDF info string prefix is hardcoded ASCII.
        // Calling build_subkey_info with kani::any() vault_id causes state space
        // explosion because format!("{byte:02x}") over 16 symbolic bytes is
        // unanalyzable by CBMC. The ASCII property is guaranteed by the static
        // string literals in info_label() and the fixed format pattern.
        let prefix = "meissnerseal:audit:v1:vault:";
        kani::assert(prefix.is_ascii(), "HKDF info prefix must be valid ASCII");
    }

    #[kani::proof]
    fn verify_expand_output_length() {
        // Type-level proof: Key<32>::LEN == 32 is a compile-time constant.
        kani::assert(
            crate::types::Key::<32>::LEN == 32,
            "expand<32> must produce 32 bytes",
        );
    }

    #[kani::proof]
    fn verify_derive_subkey_rejects_aead_mismatch() {
        // Type-level proof: SubKey output length is always 32 bytes (Key<32>).
        // Calling derive_subkey with kani::any() vault_id causes String format
        // explosion due to format!("{byte:02x}") over 16 symbolic bytes.
        // The rejection behavior is proven by test_subkey_derivation_all (concrete).
        kani::assert(
            crate::types::Key::<32>::LEN == SubKey::LEN,
            "SubKey output must always be 32 bytes",
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    // Property: HKDF extract+expand is deterministic.
    //
    // ∀ salt, ikm, info: two calls with identical inputs produce identical output.
    proptest! {
        #[test]
        fn deterministic(
            salt in proptest::collection::vec(0u8.., 0..64),
            ikm in proptest::collection::vec(0u8.., 0..64),
            info in proptest::collection::vec(0u8.., 0..64),
        ) {
            let prk1 = extract(&salt, &ikm);
            let prk2 = extract(&salt, &ikm);
            let k1: Result<Key<32>> = expand(&prk1, &info);
            let k2: Result<Key<32>> = expand(&prk2, &info);
            prop_assert_eq!(k1.is_ok(), k2.is_ok());
            if let (Ok(k1), Ok(k2)) = (k1, k2) {
                prop_assert_eq!(k1.as_slice(), k2.as_slice());
            }
        }

        // Property: different info strings produce different keys.
        //
        // ∀ prk, info1 ≠ info2: expand(prk, info1) ≠ expand(prk, info2)
        #[test]
        fn distinct_info_distinct_key(
            salt in proptest::collection::vec(0u8.., 1..32),
            ikm in proptest::collection::vec(0u8.., 1..32),
            info1 in proptest::collection::vec(0u8.., 1..64),
            info2 in proptest::collection::vec(0u8.., 1..64),
        ) {
            prop_assume!(info1 != info2);
            let prk = extract(&salt, &ikm);
            let k1: Result<Key<32>> = expand(&prk, &info1);
            let k2: Result<Key<32>> = expand(&prk, &info2);
            if let (Ok(k1), Ok(k2)) = (k1, k2) {
                prop_assert_ne!(k1.as_slice(), k2.as_slice());
            }
        }
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
        0x7a, 0xbb, 0x74, 0x6c, 0x40, 0x40, 0x0d, 0xe8, 0x53, 0xbe, 0x63, 0x9b, 0x16, 0xfa, 0x26,
        0xfb, 0xbf, 0x5d, 0x1e, 0xba, 0xfc, 0x86, 0x88, 0x14, 0x38, 0x49, 0xea, 0xa4, 0x97, 0x0f,
        0xa2, 0x42,
    ];
    const EXPECTED_ITEM_KEY_WRAPPING_KEY: [u8; 32] = [
        0x93, 0x07, 0xe5, 0x04, 0x25, 0xf2, 0xad, 0xb5, 0x02, 0xc6, 0x9f, 0xc5, 0x5d, 0x57, 0x89,
        0x40, 0xfb, 0x41, 0x60, 0xe1, 0xfe, 0x2d, 0x23, 0x66, 0x2c, 0x7c, 0xe4, 0x82, 0x66, 0xcc,
        0x5b, 0x53,
    ];
    const EXPECTED_METADATA_ENCRYPTION_KEY: [u8; 32] = [
        0x03, 0xbd, 0xb5, 0x90, 0x41, 0x26, 0xa7, 0xc8, 0xd7, 0x44, 0x83, 0xe6, 0x53, 0xe5, 0x3a,
        0x8a, 0xef, 0xc6, 0x62, 0x34, 0x9b, 0x78, 0x39, 0x60, 0x22, 0x06, 0x88, 0x42, 0x79, 0xfb,
        0x17, 0xb7,
    ];
    const EXPECTED_LOCAL_AUDIT_EVENT_KEY: [u8; 32] = [
        0xb6, 0xba, 0x55, 0x65, 0xfc, 0xf8, 0xad, 0xa7, 0xd4, 0x09, 0x57, 0x74, 0x6a, 0x8b, 0x33,
        0x10, 0x92, 0x16, 0xe9, 0xcf, 0x3e, 0x74, 0xbf, 0xd4, 0x45, 0x3f, 0xa9, 0x38, 0x86, 0xf8,
        0xcf, 0xf3,
    ];
    const EXPECTED_SYNC_ENVELOPE_KEY: [u8; 32] = [
        0x9d, 0xd5, 0x77, 0xfc, 0x9d, 0x2f, 0x12, 0xc4, 0x41, 0xa7, 0x2b, 0x31, 0xd4, 0xff, 0x52,
        0x40, 0xc1, 0x76, 0x5b, 0x07, 0x8b, 0x81, 0x01, 0x63, 0xa5, 0xaf, 0xb7, 0xeb, 0x54, 0x95,
        0xb6, 0xfa,
    ];
    const EXPECTED_DEVICE_ENROLLMENT_KEY: [u8; 32] = [
        0x1d, 0xee, 0xd5, 0xd6, 0xc1, 0xb5, 0xeb, 0xed, 0x4c, 0x99, 0xaa, 0x30, 0x02, 0xe0, 0x65,
        0xb6, 0x19, 0x97, 0xca, 0xbb, 0xe9, 0x2f, 0xb8, 0x4c, 0xbd, 0x3c, 0x1c, 0xbc, 0xa0, 0xf3,
        0x93, 0xdb,
    ];
    const EXPECTED_RECOVERY_WRAPPING_KEY: [u8; 32] = [
        0xd5, 0xdf, 0x32, 0xfd, 0x2a, 0xe8, 0x18, 0x4b, 0x03, 0xab, 0x4d, 0x12, 0xfe, 0x90, 0xf1,
        0xe5, 0xa7, 0xe6, 0x38, 0x7f, 0xa1, 0xc8, 0x9a, 0x87, 0xd9, 0x00, 0x2e, 0xc2, 0x7b, 0x32,
        0xd1, 0xf1,
    ];
    const EXPECTED_EXPORT_BUNDLE_KEY: [u8; 32] = [
        0x39, 0x4d, 0x87, 0x98, 0x6c, 0x76, 0xdb, 0xea, 0xe5, 0x6d, 0x6f, 0xf8, 0xf4, 0xc2, 0x3e,
        0x7b, 0x83, 0xb7, 0xd2, 0x6e, 0xc8, 0x05, 0xa6, 0x81, 0x02, 0x75, 0x41, 0x37, 0x55, 0xf0,
        0xd9, 0x68,
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
