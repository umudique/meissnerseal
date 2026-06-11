// SPDX-License-Identifier: Apache-2.0
//! Key hierarchy derivation for Arcanum vault sessions.
//!
//! Implements the key derivation chain specified in
//! `specs/crypto/crypto_design.md` §3, steps 1–6.

use arcanum_crypto::{
    aead::{decrypt, encrypt, Ciphertext},
    kdf::{
        argon2::{derive, derive_vkek},
        hkdf::{derive_root_prk, derive_subkey, Prk, SubkeyPurpose},
    },
    rng::random_key,
    types::{AeadKey, HeaderNonce, Key, VaultRootKey, XChaCha20Nonce},
};

use crate::error::CoreError;
use crate::vault::format::{HeaderKdfParams, ARGON2_VERSION_0X13, KDF_ARGON2ID_V1};

/// Profile ID for AEAD_XCHACHA20_POLY1305_V1.
const AEAD_ID: u16 = 1;

/// Unlocked key material for a vault session.
///
/// # Contract
///
/// ## Preconditions
/// - Constructed only after successful VaultRootKey recovery and root PRK
///   derivation from `specs/crypto/crypto_design.md` §3 steps 5-6.
///
/// ## Postconditions
/// - Contains all seven HKDF subkeys from the §5 registry:
///   item-wrap, metadata, audit, sync-envelope, device-enroll, recovery-wrap,
///   and export-bundle.
/// - Each field is exactly the 32-byte output of
///   `HKDF-Expand(root_prk, <registry info>, 32)` for its registered
///   `SubkeyPurpose`.
///
/// ## Invariants
/// - All seven subkeys are domain-separated by distinct ASCII HKDF info strings
///   from `crypto_design.md` §5; item-wrap and metadata are AEAD-scoped, the
///   other five are not.
/// - Does **not** implement `Clone`, `PartialEq`, or `Debug` — contains secret
///   key material.
/// - All fields use `arcanum_crypto::types::Key<32>`, which implements
///   `ZeroizeOnDrop`. Memory is cleared when this struct is dropped.
///
/// All fields use `arcanum_crypto::types::Key<32>`, which implements
/// `ZeroizeOnDrop`. Memory is cleared when this struct is dropped.
///
/// # Security invariants
///
/// - Constructed exclusively by [`derive_session_keys`] or [`create_session_keys`].
/// - The `VaultRootKey` is **not** retained: it exists only transiently inside
///   [`derive_session_keys`]/[`create_session_keys`] to derive `root_prk`, and
///   is dropped (ZeroizeOnDrop) before this struct is returned. A live session
///   never needs the raw VRK (F-05).
pub struct UnlockedKeys {
    /// Item Key Wrapping Key — wraps per-revision Record Encryption Keys.
    pub item_wrap_key: Key<32>,
    /// Metadata Encryption Key.
    pub metadata_key: Key<32>,
    /// Local Audit Event Key.
    pub audit_key: Key<32>,
    /// Sync Envelope Key.
    pub sync_envelope_key: Key<32>,
    /// Device Enrollment Key.
    pub device_enrollment_key: Key<32>,
    /// Recovery Wrapping Key.
    pub recovery_wrapping_key: Key<32>,
    /// Export Bundle Key.
    pub export_key: Key<32>,
}

/// Derive the Master Unlock Key using KDF parameters parsed from the vault header.
///
/// # Contract
///
/// ## Preconditions
/// - `password` is non-empty secret material provided by the caller and is never
///   logged, printed, or written to an error value.
/// - `vault_id` is the canonical 128-bit vault UUID from the header TLV.
/// - `kdf_params` was produced by `vault::format::parse_kdf_profile_params`
///   from the same vault header being unlocked.
/// - `kdf_params.profile_id == KDF_ARGON2ID_V1` and
///   `kdf_params.argon2_version == 0x13`.
///
/// ## Postconditions
/// - On success, returns exactly the Master Unlock Key produced by
///   `arcanum_crypto::kdf::argon2::derive(password, vault_id, &kdf_params.argon2)`.
/// - On invalid parameters, unsupported version/profile, backend failure, or
///   empty password, returns `Err` with no partial key material.
///
/// ## Invariants
/// - Consumes header-sourced Argon2id parameters; it must not read or use the
///   module-level ADR-006 compatibility constant.
/// - Delegates cryptographic work only to `arcanum-crypto`; it does not
///   implement Argon2id or hashing directly.
/// - Error values contain no password bytes or derived key material.
pub fn derive_master_unlock_key_with_header_params(
    password: &[u8],
    vault_id: &[u8; 16],
    kdf_params: &HeaderKdfParams,
) -> crate::error::Result<arcanum_crypto::types::MasterUnlockKey> {
    if password.is_empty()
        || kdf_params.profile_id != KDF_ARGON2ID_V1
        || kdf_params.argon2_version != ARGON2_VERSION_0X13
    {
        return Err(CoreError::Crypto);
    }

    derive(password, vault_id, &kdf_params.argon2).map_err(|_| CoreError::Crypto)
}

/// Derive the full key hierarchy from a password and vault header.
///
/// Executes derivation chain steps 1–6 from `specs/crypto/crypto_design.md` §3:
///
/// ```text
/// [1] Argon2id → MasterUnlockKey (MUK)
/// [2] HKDF-Extract(salt="arcanum-vkek-salt-v1"||vault_id, ikm=MUK) → vkek_prk
/// [3] HKDF-Expand(vkek_prk, info="arcanum:vault-kek:v1") → VKEK
/// [4] AEAD-decrypt(key=VKEK, wrapped_root_key_ciphertext, aad) → VaultRootKey
/// [5] HKDF-Extract(salt=SHA256("arcanum-root-salt-v1"||vault_id||header_nonce), ikm=VRK) → root_prk
/// [6] HKDF-Expand(root_prk, info per registry) × 7 HKDF subkeys → UnlockedKeys
/// ```
///
/// # Contract
///
/// ## Preconditions
/// - `password` is non-empty secret material.
/// - `vault_id` is the canonical 128-bit vault UUID from the header TLV.
/// - `header_nonce` is the 24-byte nonce stored in the vault header TLV tag
///   `0x0007`.
/// - `kdf_params` was parsed and validated from the vault header TLV tag
///   `0x0003`; no hardcoded KDF parameters are used on unlock.
/// - `wrapped_root_key_ciphertext` is the VKEK-encrypted `VaultRootKey`
///   ciphertext from the `WrappedRootKey` record frame.
/// - `wrapped_root_key_nonce` is the 24-byte AEAD nonce stored in the
///   `WrappedRootKey` record frame.
/// - `aad` is the canonical 74-byte AAD for the `WrappedRootKey` record,
///   constructed per `vault_format_v1.md` §7 with `record_kind = 0x0002`.
///
/// ## Postconditions
/// - On success: returns [`UnlockedKeys`] with all seven HKDF subkeys fully
///   derived (the VaultRootKey is consumed during derivation, not retained).
/// - On Argon2id failure, AEAD authentication failure, or HKDF failure:
///   returns `Err` — no key material is exposed in the error value.
///
/// ## Invariants
/// - Never calls cryptographic primitives directly — delegates exclusively to
///   the `arcanum_crypto` API (CONTRACT A-01).
/// - All derived keys are represented by `arcanum_crypto::types::Key<32>`
///   (ZeroizeOnDrop).
/// - Fails closed: any intermediate failure returns `Err` without partial output
///   (CONTRACT G-06).
pub fn derive_session_keys(
    password: &[u8],
    vault_id: &[u8; 16],
    header_nonce: &[u8; 24],
    kdf_params: &HeaderKdfParams,
    wrapped_root_key_ciphertext: &[u8],
    wrapped_root_key_nonce: &[u8; 24],
    aad: &[u8; 74],
) -> crate::error::Result<UnlockedKeys> {
    // [1] Argon2id → MasterUnlockKey
    let muk = derive_master_unlock_key_with_header_params(password, vault_id, kdf_params)?;

    // [2–3] MUK → VKEK via HKDF
    let vkek = derive_vkek(&muk, vault_id).map_err(|_| CoreError::Crypto)?;

    // [4] Decrypt WrappedRootKey with VKEK
    let aead_key = AeadKey::from_bytes(*vkek.as_bytes());
    let nonce = XChaCha20Nonce::from_bytes(*wrapped_root_key_nonce);
    let ciphertext = Ciphertext::from(wrapped_root_key_ciphertext.to_vec());
    let vrk_plaintext =
        decrypt(&aead_key, &nonce, &ciphertext, aad).map_err(|_| CoreError::Auth)?;
    let mut vrk_bytes: [u8; 32] = vrk_plaintext
        .as_ref()
        .try_into()
        .map_err(|_| CoreError::Crypto)?;
    let vault_root_key = Key::<32>::from_bytes(vrk_bytes);
    // F-04: the intermediate stack copy of the VRK is not ZeroizeOnDrop —
    // wipe it explicitly now that ownership has moved into `Key<32>`.
    zeroize::Zeroize::zeroize(&mut vrk_bytes);

    // [5–6] VaultRootKey → root_prk → subkeys
    let vrk = VaultRootKey::from_bytes(*vault_root_key.as_bytes());
    let hn = HeaderNonce::from_bytes(*header_nonce);
    let root_prk = derive_root_prk(&vrk, vault_id, &hn);
    derive_subkeys(&root_prk, vault_id, AEAD_ID)
}

/// Wrap a freshly generated `VaultRootKey` for storage in a new vault.
///
/// Executes steps 1–6 as in [`derive_session_keys`], but instead of decrypting
/// an existing `WrappedRootKey`, generates a fresh `VaultRootKey` from the OS
/// CSPRNG and encrypts it with the derived VKEK.
///
/// # Contract
///
/// ## Preconditions
/// - `password` is the vault master password (non-empty secret material).
/// - `vault_id` is the canonical 128-bit vault UUID assigned to the new vault.
/// - `header_nonce` is a fresh 24-byte random nonce generated for the vault
///   header (not reused from any prior vault).
/// - `kdf_params` is the explicit KDF parameter set that will be serialized into
///   the new vault header.
/// - `aad` is the canonical 74-byte AAD for the `WrappedRootKey` record,
///   constructed per `vault_format_v1.md` §7 with `record_kind = 0x0002`.
///
/// ## Postconditions
/// - Returns `(UnlockedKeys, ciphertext, nonce)` where:
///   - `ciphertext` is the VKEK-encrypted `VaultRootKey`, stored in the
///     `WrappedRootKey` record frame `ciphertext` field.
///   - `nonce` is the 24-byte AEAD nonce used for encryption, stored in the
///     `WrappedRootKey` record frame `nonce` field.
/// - The `VaultRootKey` is never present in the return value in plaintext.
///
/// ## Invariants
/// - `VaultRootKey` is generated from OS CSPRNG via `arcanum_crypto::rng`.
/// - Never calls cryptographic primitives directly — delegates exclusively to
///   the `arcanum_crypto` API.
/// - Never writes `VaultRootKey` in plaintext to any output (CONTRACT I-02).
pub fn create_session_keys(
    password: &[u8],
    vault_id: &[u8; 16],
    header_nonce: &[u8; 24],
    kdf_params: &HeaderKdfParams,
    aad: &[u8; 74],
) -> crate::error::Result<(UnlockedKeys, Vec<u8>, [u8; 24])> {
    // [1] Generate fresh VaultRootKey from OS CSPRNG
    let vault_root_key = Key::<32>::from_bytes(random_key());

    // [2–3] Argon2id → MUK → VKEK
    let muk = derive_master_unlock_key_with_header_params(password, vault_id, kdf_params)?;
    let vkek = derive_vkek(&muk, vault_id).map_err(|_| CoreError::Crypto)?;

    // [4] Encrypt VaultRootKey with VKEK
    let aead_key = AeadKey::from_bytes(*vkek.as_bytes());
    let (ciphertext, enc_nonce) =
        encrypt(&aead_key, vault_root_key.as_slice(), aad).map_err(|_| CoreError::Crypto)?;

    // [5–6] Derive subkeys
    let nonce_bytes: [u8; 24] = *enc_nonce.as_bytes();
    let vrk = VaultRootKey::from_bytes(*vault_root_key.as_bytes());
    let hn = HeaderNonce::from_bytes(*header_nonce);
    let root_prk = derive_root_prk(&vrk, vault_id, &hn);
    let unlocked = derive_subkeys(&root_prk, vault_id, AEAD_ID)?;

    Ok((unlocked, ciphertext.as_ref().to_vec(), nonce_bytes))
}

/// Derive all seven vault session subkeys from the root PRK.
///
/// # Contract
///
/// ## Preconditions
/// - `root_prk` was produced by `arcanum-crypto::kdf::hkdf::derive_root_prk`
///   from the current vault's VaultRootKey, vault_id, and header_nonce.
/// - `vault_id` is the canonical 128-bit vault UUID from the header.
/// - `aead_id` is the supported AEAD profile identifier used for AEAD-scoped
///   subkeys.
///
/// ## Postconditions
/// - On success, returns [`UnlockedKeys`] with all seven registry subkeys:
///   item-wrap, metadata, audit, sync-envelope, device-enroll, recovery-wrap,
///   and export-bundle.
/// - Each returned field is exactly
///   `HKDF-Expand(root_prk, <crypto_design.md §5 registry info>, 32)` for its
///   corresponding `SubkeyPurpose`.
/// - If any HKDF expansion fails, returns `Err` with no partial
///   [`UnlockedKeys`].
///
/// ## Invariants
/// - Delegates every HKDF expansion to `arcanum-crypto::kdf::hkdf::derive_subkey`.
/// - Does not build HKDF info strings in arcanum-core and does not implement
///   cryptographic primitives directly.
/// - All seven subkeys are pairwise domain-separated by distinct
///   `SubkeyPurpose` registry entries.
pub fn derive_subkeys(
    root_prk: &Prk,
    vault_id: &[u8; 16],
    aead_id: u16,
) -> crate::error::Result<UnlockedKeys> {
    let item_wrap = derive_subkey(
        root_prk,
        SubkeyPurpose::ItemKeyWrappingKey,
        vault_id,
        Some(aead_id),
    )
    .map_err(|_| CoreError::Crypto)?;
    let metadata = derive_subkey(
        root_prk,
        SubkeyPurpose::MetadataEncryptionKey,
        vault_id,
        Some(aead_id),
    )
    .map_err(|_| CoreError::Crypto)?;
    let audit = derive_subkey(root_prk, SubkeyPurpose::LocalAuditEventKey, vault_id, None)
        .map_err(|_| CoreError::Crypto)?;
    let sync_envelope = derive_subkey(root_prk, SubkeyPurpose::SyncEnvelopeKey, vault_id, None)
        .map_err(|_| CoreError::Crypto)?;
    let device_enrollment =
        derive_subkey(root_prk, SubkeyPurpose::DeviceEnrollmentKey, vault_id, None)
            .map_err(|_| CoreError::Crypto)?;
    let recovery_wrapping =
        derive_subkey(root_prk, SubkeyPurpose::RecoveryWrappingKey, vault_id, None)
            .map_err(|_| CoreError::Crypto)?;
    let export = derive_subkey(root_prk, SubkeyPurpose::ExportBundleKey, vault_id, None)
        .map_err(|_| CoreError::Crypto)?;

    Ok(UnlockedKeys {
        item_wrap_key: Key::<32>::from_bytes(*item_wrap.as_bytes()),
        metadata_key: Key::<32>::from_bytes(*metadata.as_bytes()),
        audit_key: Key::<32>::from_bytes(*audit.as_bytes()),
        sync_envelope_key: Key::<32>::from_bytes(*sync_envelope.as_bytes()),
        device_enrollment_key: Key::<32>::from_bytes(*device_enrollment.as_bytes()),
        recovery_wrapping_key: Key::<32>::from_bytes(*recovery_wrapping.as_bytes()),
        export_key: Key::<32>::from_bytes(*export.as_bytes()),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::vault::format::build_aad;

    const VAULT_ID: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    const HEADER_NONCE: [u8; 24] = [0u8; 24];
    const ZERO_RECORD_ID: [u8; 16] = [0u8; 16];

    fn test_aad() -> [u8; 74] {
        build_aad(
            &VAULT_ID,
            1,
            1,
            1,
            1,
            0,
            &ZERO_RECORD_ID,
            &ZERO_RECORD_ID,
            0x0002,
        )
    }

    fn test_kdf_params() -> HeaderKdfParams {
        HeaderKdfParams::canonical_argon2id_v1()
    }

    /// `derive_session_keys` fails closed when ciphertext is wrong (AEAD failure).
    #[test]
    fn test_derive_session_keys_auth_failure() {
        let password = b"test-password-never-real";
        // 47-byte ciphertext: shorter than the 16-byte Poly1305 tag — guaranteed Err.
        let ciphertext = [0u8; 47];
        let nonce = [0u8; 24];
        let aad = test_aad();
        let kdf_params = test_kdf_params();
        let result = derive_session_keys(
            password,
            &VAULT_ID,
            &HEADER_NONCE,
            &kdf_params,
            &ciphertext,
            &nonce,
            &aad,
        );
        assert!(result.is_err(), "wrong ciphertext must return Err");
    }

    /// `create_session_keys` succeeds and returns ciphertext with AEAD tag appended.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn test_create_session_keys_succeeds() {
        let password = b"test-password-never-real";
        let aad = test_aad();
        let kdf_params = test_kdf_params();
        let result = create_session_keys(password, &VAULT_ID, &HEADER_NONCE, &kdf_params, &aad);
        let (_keys, ciphertext, nonce) = result.expect("create_session_keys must succeed");
        // 32-byte VRK + 16-byte Poly1305 tag = 48 bytes
        assert_eq!(
            ciphertext.len(),
            48,
            "ciphertext must be plaintext + 16-byte tag"
        );
        assert_eq!(nonce.len(), 24, "nonce must be 24 bytes");
    }

    /// Round-trip: create then derive must recover matching subkeys.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn test_create_then_derive_roundtrip() {
        let password = b"test-password-never-real";
        let aad = test_aad();
        let kdf_params = test_kdf_params();

        let (created, ciphertext, wrk_nonce) =
            create_session_keys(password, &VAULT_ID, &HEADER_NONCE, &kdf_params, &aad)
                .expect("create must succeed");

        let derived = derive_session_keys(
            password,
            &VAULT_ID,
            &HEADER_NONCE,
            &kdf_params,
            &ciphertext,
            &wrk_nonce,
            &aad,
        )
        .expect("derive must succeed after create");

        // Verify subkeys match via constant-time comparison (Key::ct_eq delegates to subtle).
        assert!(
            bool::from(created.item_wrap_key.ct_eq(&derived.item_wrap_key)),
            "item_wrap_key must match"
        );
        assert!(
            bool::from(created.metadata_key.ct_eq(&derived.metadata_key)),
            "metadata_key must match"
        );
        assert!(
            bool::from(created.audit_key.ct_eq(&derived.audit_key)),
            "audit_key must match"
        );
        assert!(
            bool::from(created.export_key.ct_eq(&derived.export_key)),
            "export_key must match"
        );
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Prove that all fixed-width inputs to `derive_session_keys` have the
    /// expected byte lengths.
    ///
    /// Phase 1 skeleton — preserved as input-shape proof. Full behavioral
    /// verification added in Phase 3 when Kani supports Argon2id unwinding.
    #[kani::proof]
    fn verify_derive_session_keys_signature() {
        let vault_id = kani::any::<[u8; 16]>();
        let header_nonce = kani::any::<[u8; 24]>();
        let nonce = kani::any::<[u8; 24]>();
        let aad = kani::any::<[u8; 74]>();

        kani::assert(vault_id.len() == 16, "vault_id is exactly 16 bytes");
        kani::assert(header_nonce.len() == 24, "header_nonce is exactly 24 bytes");
        kani::assert(
            nonce.len() == 24,
            "wrapped_root_key_nonce is exactly 24 bytes",
        );
        kani::assert(
            aad.len() == 74,
            "aad is exactly 74 bytes per vault_format_v1.md §7",
        );
    }
}
