// SPDX-License-Identifier: Apache-2.0
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
/// # Contract
///
/// ## Preconditions
/// - Constructed by callers with item plaintext that must be encrypted before
///   persistence.
/// - `secret` contains plaintext item bytes and must not be logged, formatted,
///   or written to disk outside the encrypted item-record path.
///
/// ## Postconditions
/// - Ownership of plaintext is transferred to item operations such as
///   `item::add` and `item::update`; those operations must either encrypt and
///   persist the item or return `Err` without partial output.
///
/// ## Invariants
/// - This type intentionally does not implement `Clone`, `PartialEq`, or
///   `Debug`.
/// - Plaintext item payload is exposed only through `SecretBytes` scoped access.
/// - Metadata (`label`, `tags`) must be encrypted into the item payload where
///   possible; cleartext table metadata is limited to routing fields required by
///   `vault_format_v1.md` §5.
///
/// This type intentionally does not implement `Clone`, `PartialEq`, or `Debug`.
pub struct PlainItem {
    /// Item kind.
    pub kind: ItemKind,

    /// Non-secret display label.
    pub label: String,

    /// Secret item payload.
    pub secret: meissnerseal_security::secret_lifecycle::SecretBytes,

    /// Non-secret display tags.
    pub tags: Vec<String>,
}

/// Closure-scoped plaintext item view.
///
/// # Contract
///
/// ## Preconditions
/// - Constructed only by `item::with_item` after successful item-frame
///   authentication, REK unwrap under IKWK, and payload decrypt under the REK.
/// - The referenced plaintext is live only for the duration of the
///   `with_item` closure.
///
/// ## Postconditions
/// - Provides read-only borrowed access to item kind, metadata, and secret
///   payload.
/// - The view cannot outlive the closure borrow; callers never receive an owned
///   plaintext item from `with_item` (CONTRACT G-02).
///
/// ## Invariants
/// - Does not implement `Clone`, `PartialEq`, `Debug`, `Display`, or
///   serialization.
/// - Secret bytes remain behind `SecretBytes::with_secret`; this view does not
///   transfer ownership of plaintext bytes.
/// - No plaintext is written to disk, logs, or error values.
pub struct PlainItemView<'a> {
    /// Item kind.
    pub kind: &'a ItemKind,

    /// Decrypted item label. Borrowed and closure-scoped.
    pub label: &'a str,

    /// Decrypted item tags. Borrowed and closure-scoped.
    pub tags: &'a [String],

    /// Decrypted item payload. Borrowed and closure-scoped.
    pub secret: &'a meissnerseal_security::secret_lifecycle::SecretBytes,
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
#[allow(clippy::expect_used)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    // Property: from_u16(as_u16(k)) == Ok(k) for every valid ItemKind.
    //
    // Uses an index strategy over the known variants rather than raw u16
    // (most u16 values are invalid; prop_assume on those wastes test budget).
    proptest! {
        #[test]
        fn item_kind_codec(wire in proptest::prop_oneof![
            Just(0x0001u16),
            Just(0x0002u16),
            Just(0x0003u16),
            Just(0x0004u16),
            Just(0x0005u16),
        ]) {
            let kind = ItemKind::from_u16(wire).expect("known wire value must parse");
            prop_assert_eq!(kind.as_u16(), wire);
        }

        // Property: unknown wire values are always rejected.
        #[test]
        fn unknown_wire_value_rejected(v in 0x0006u16..) {
            prop_assert!(ItemKind::from_u16(v).is_err());
        }
    }
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
