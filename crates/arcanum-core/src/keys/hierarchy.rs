//! Key hierarchy derivation for Arcanum vault sessions.
//!
//! Implements the key derivation chain specified in
//! `specs/crypto/crypto_design.md` §3, steps 1–6.
//!
//! Phase 1 — contracts, type definitions, and test skeletons.
//! Function bodies are intentionally unimplemented (`todo!()`).
// REASON: Phase 1 per AGENTS.md §12 — all function bodies are stubs awaiting
// human approval before Phase 2 implementation begins.
#![allow(clippy::todo)]

use arcanum_crypto::types::Key;

/// Unlocked key material for a vault session.
///
/// All fields use `arcanum_crypto::types::Key<32>`, which implements
/// `ZeroizeOnDrop`. Memory is cleared when this struct is dropped.
///
/// # Security invariants
///
/// - Does **not** implement `Clone`, `PartialEq`, or `Debug` — contains secret
///   key material.
/// - Constructed exclusively by [`derive_session_keys`] or [`create_session_keys`].
/// - Subkeys sync, device-enroll, and recovery are omitted for MVP-0.
pub struct UnlockedKeys {
    /// Vault Root Key — unwrapped from the `WrappedRootKey` record.
    pub vault_root_key: Key<32>,
    /// Item Key Wrapping Key — wraps per-revision Record Encryption Keys.
    pub item_wrap_key: Key<32>,
    /// Metadata Encryption Key.
    pub metadata_key: Key<32>,
    /// Local Audit Event Key.
    pub audit_key: Key<32>,
    /// Export Bundle Key.
    pub export_key: Key<32>,
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
/// [6] HKDF-Expand(root_prk, info per registry) × 5 subkeys → UnlockedKeys
/// ```
///
/// # Contract
///
/// ## Preconditions
/// - `password` is non-empty secret material.
/// - `vault_id` is the canonical 128-bit vault UUID from the header TLV.
/// - `header_nonce` is the 24-byte nonce stored in the vault header TLV tag
///   `0x0007`.
/// - `wrapped_root_key_ciphertext` is the VKEK-encrypted `VaultRootKey`
///   ciphertext from the `WrappedRootKey` record frame.
/// - `wrapped_root_key_nonce` is the 24-byte AEAD nonce stored in the
///   `WrappedRootKey` record frame.
/// - `aad` is the canonical 74-byte AAD for the `WrappedRootKey` record,
///   constructed per `vault_format_v1.md` §7 with `record_kind = 0x0002`.
///
/// ## Postconditions
/// - On success: returns [`UnlockedKeys`] with all five subkeys fully derived.
/// - On Argon2id failure, AEAD authentication failure, or HKDF failure:
///   returns `Err` — no key material is exposed in the error value.
///
/// ## Invariants
/// - Never calls cryptographic primitives directly — delegates exclusively to
///   the `arcanum_crypto` API (CONTRACT A-01 / anti-guarantee).
/// - All derived keys are represented by `arcanum_crypto::types::Key<32>`
///   (ZeroizeOnDrop).
/// - Fails closed: any intermediate failure returns `Err` without partial output
///   (CONTRACT G-06).
pub fn derive_session_keys(
    password: &[u8],
    vault_id: &[u8; 16],
    header_nonce: &[u8; 24],
    wrapped_root_key_ciphertext: &[u8],
    wrapped_root_key_nonce: &[u8; 24],
    aad: &[u8; 74],
) -> crate::error::Result<UnlockedKeys> {
    let _ = (
        password,
        vault_id,
        header_nonce,
        wrapped_root_key_ciphertext,
        wrapped_root_key_nonce,
        aad,
    );
    todo!()
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
    aad: &[u8; 74],
) -> crate::error::Result<(UnlockedKeys, Vec<u8>, [u8; 24])> {
    let _ = (password, vault_id, header_nonce, aad);
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Phase 1 stub confirmation: `derive_session_keys` panics via `todo!()`.
    #[test]
    #[should_panic]
    fn test_derive_session_keys_is_stubbed() {
        let password = b"stub-test-password";
        let vault_id = [0u8; 16];
        let header_nonce = [0u8; 24];
        let ciphertext: &[u8] = &[];
        let nonce = [0u8; 24];
        let aad = [0u8; 74];
        let _ = derive_session_keys(password, &vault_id, &header_nonce, ciphertext, &nonce, &aad);
    }

    /// Phase 1 stub confirmation: `create_session_keys` panics via `todo!()`.
    #[test]
    #[should_panic]
    fn test_create_session_keys_is_stubbed() {
        let password = b"stub-test-password";
        let vault_id = [0u8; 16];
        let header_nonce = [0u8; 24];
        let aad = [0u8; 74];
        let _ = create_session_keys(password, &vault_id, &header_nonce, &aad);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Prove that all fixed-width inputs to `derive_session_keys` have the
    /// expected byte lengths.
    ///
    /// Phase 1 skeleton — the function body is `todo!()`, so no assertion on
    /// the return value is possible. This harness proves that the input type
    /// constraints are well-formed for all concrete input shapes.
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
        // Phase 2: call derive_session_keys here and assert on the result.
    }
}
