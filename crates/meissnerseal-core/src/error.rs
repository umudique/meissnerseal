// SPDX-License-Identifier: Apache-2.0
//! Core crate error types.

/// Error type for meissnerseal-core operations.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Vault binary format parsing or validation failed.
    #[error("vault format error: {0}")]
    Format(String),

    /// Authentication failed.
    #[error("authentication failed")]
    Auth,

    /// Referenced item was not found.
    #[error("item not found: {0}")]
    NotFound(String),

    /// Operation was attempted in an invalid state.
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Cryptographic provider returned an error.
    #[error("crypto error")]
    Crypto,

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Import failed mid-way and rollback could not remove all partial items.
    /// The vault is in an inconsistent state; caller must treat it as corrupted.
    #[error("partial import: rollback failed, vault may be inconsistent")]
    PartialImport,
}

/// Core crate result type.
pub type Result<T> = core::result::Result<T, CoreError>;
