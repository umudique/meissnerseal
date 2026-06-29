// SPDX-License-Identifier: Apache-2.0
/// Fixed-length cryptographic types with compile-time length enforcement.
/// All secret material must use these types. See ADR-015.
pub mod types;
pub use types::{
    AeadKey, AesGcmNonce, DerivedSubkey, HeaderNonce, HkdfPrk, Key, MasterUnlockKey, RecordEncKey,
    RecordId, RevisionId, TransferPayloadKey, VaultId, VaultKeyEncKey, VaultRootKey,
    XChaCha20Nonce,
};

pub mod aead;
pub mod hash;
pub mod kdf;
pub mod rng;
pub mod subtle;
pub mod test_vectors;
pub mod zeroize;

pub use kdf::argon2;
pub use kdf::hkdf;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_argon2_module_re_exports_kdf_implementation() {
        let _: argon2::Argon2Params = kdf::argon2::Argon2Params {
            m_cost_kib: 65_536,
            t_cost: 3,
            p_lanes: 4,
            output_len: MasterUnlockKey::LEN,
        };
    }

    #[test]
    fn top_level_hkdf_module_re_exports_kdf_implementation() {
        let purpose = hkdf::SubkeyPurpose::LocalAuditEventKey;
        assert!(matches!(
            purpose,
            kdf::hkdf::SubkeyPurpose::LocalAuditEventKey
        ));
    }
}
