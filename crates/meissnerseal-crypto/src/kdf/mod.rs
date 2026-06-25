// SPDX-License-Identifier: Apache-2.0
//! Key derivation functions for MeissnerSeal vault cryptography.
//!
//! Provides Argon2id passphrase hardening and HKDF-SHA256 subkey derivation
//! for the vault key hierarchy (MUK → VKEK → VRK → session subkeys).

pub mod argon2;
pub mod hkdf;

pub use argon2::Argon2Params;
pub use hkdf::{derive_root_prk, Prk, SubKey, SubkeyPurpose};

/// KDF module error.
#[derive(Debug, thiserror::Error)]
pub enum KdfError {
    /// The caller provided invalid parameters or invalid domain inputs.
    #[error("invalid KDF input")]
    InvalidInput,

    /// The underlying cryptographic backend rejected the operation.
    #[error("KDF backend error")]
    Backend,
}

/// KDF module result type.
pub type Result<T> = core::result::Result<T, KdfError>;

#[cfg(test)]
mod tests {}
