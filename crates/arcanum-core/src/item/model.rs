//! Item model contracts.

use crate::error::{CoreError, Result};

/// 128-bit random item identifier.
pub type ItemId = [u8; 16];

/// Item kind registry.
///
/// Debug is intentionally derived: ItemKind is a type discriminant, not secret
/// material. Variant names (Password, SeedPhrase, etc.) are metadata, not payloads.
#[derive(Debug)]
pub enum ItemKind {
    /// Password item.
    Password,

    /// Seed phrase item.
    SeedPhrase,

    /// SSH private key item.
    SshPrivateKey,

    /// API token item.
    ApiToken,

    /// Secure note item.
    SecureNote,
}

impl ItemKind {
    /// Return the wire-format item kind value.
    pub fn as_u16(&self) -> u16 {
        match self {
            Self::Password => 0x0001,
            Self::SeedPhrase => 0x0002,
            Self::SshPrivateKey => 0x0003,
            Self::ApiToken => 0x0004,
            Self::SecureNote => 0x0005,
        }
    }

    /// Parse an item kind from its wire-format value.
    ///
    /// # Contract
    /// ## Preconditions
    /// - `v` is an item kind value read from a trusted parser boundary.
    /// ## Postconditions
    /// - Returns a known `ItemKind` or `Err`.
    /// - Unknown values are rejected.
    /// ## Invariants
    /// - Does not include plaintext item contents in error messages.
    pub fn from_u16(v: u16) -> Result<Self> {
        match v {
            0x0001 => Ok(Self::Password),
            0x0002 => Ok(Self::SeedPhrase),
            0x0003 => Ok(Self::SshPrivateKey),
            0x0004 => Ok(Self::ApiToken),
            0x0005 => Ok(Self::SecureNote),
            _ => Err(CoreError::Format(format!("unknown item kind: {v:#06x}"))),
        }
    }
}

/// Plain item with secret payload.
///
/// This type intentionally does not implement `Clone`, `PartialEq`, or `Debug`.
pub struct PlainItem {
    /// Item kind.
    pub kind: ItemKind,

    /// Non-secret display label.
    pub label: String,

    /// Secret item payload.
    pub secret: arcanum_security::secret_lifecycle::SecretBytes,

    /// Non-secret display tags.
    pub tags: Vec<String>,
}

/// Non-secret item summary.
#[derive(Debug)]
pub struct ItemSummary {
    /// Item identifier.
    pub id: ItemId,

    /// Item kind.
    pub kind: ItemKind,

    /// Non-secret display label.
    pub label: String,

    /// Non-secret display tags.
    pub tags: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::error::CoreError;

    #[test]
    fn test_item_kind_roundtrip() {
        let variants = [
            ItemKind::Password,
            ItemKind::SeedPhrase,
            ItemKind::SshPrivateKey,
            ItemKind::ApiToken,
            ItemKind::SecureNote,
        ];

        for kind in variants {
            let parsed = ItemKind::from_u16(kind.as_u16());
            assert!(parsed.is_ok());
            assert_eq!(parsed.unwrap().as_u16(), kind.as_u16());
        }
    }

    #[test]
    fn test_item_kind_unknown_rejected() {
        assert!(matches!(
            ItemKind::from_u16(0xFFFF),
            Err(CoreError::Format(_))
        ));
    }
}
