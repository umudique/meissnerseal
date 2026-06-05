/// Fixed-length cryptographic types with compile-time length enforcement.
/// All secret material must use these types. See ADR-015.
pub mod types;
pub use types::{
    AeadKey,
    AesGcmNonce,
    DerivedSubkey,
    HeaderNonce,
    HkdfPrk,
    Key,
    MasterUnlockKey,
    RecordEncKey,
    RecordId,
    RevisionId,
    TransferPayloadKey,
    VaultId,
    VaultKeyEncKey,
    VaultRootKey,
    XChaCha20Nonce,
};

pub mod aead;
pub mod argon2;
pub mod hkdf;
pub mod rng;
pub mod subtle;
pub mod zeroize;
pub mod test_vectors;
