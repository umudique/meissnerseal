// SPDX-License-Identifier: Apache-2.0
//! Audit event contracts.

mod sealed {
    pub trait Sealed {}
}

/// Marker trait for values safe to carry in an audit event.
///
/// Sealed so only approved types (`AuditLabel`, `u64`) can satisfy the bound.
pub trait AuditSafe: sealed::Sealed {}

/// A validated, non-secret audit label (item IDs, device IDs).
///
/// Accepts at most 128 ASCII alphanumeric, `-`, or `:` characters.
#[derive(Debug, Clone)]
pub struct AuditLabel(String);

/// Error returned when an `AuditLabel` candidate fails validation.
#[derive(Debug)]
pub struct InvalidAuditLabel;

impl AuditLabel {
    /// Returns the label as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for AuditLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for AuditLabel {
    type Error = InvalidAuditLabel;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.len() > 128
            || !s
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ':')
        {
            return Err(InvalidAuditLabel);
        }
        Ok(AuditLabel(s.to_owned()))
    }
}

impl sealed::Sealed for AuditLabel {}
impl sealed::Sealed for u64 {}
impl AuditSafe for AuditLabel {}
impl AuditSafe for u64 {}

/// Non-secret audit event kind.
///
/// All fields carried by this enum must remain non-secret operational metadata.
/// Secret values, key material, plaintext item contents, passwords, recovery
/// material, `SecretBytes`, and `SecretString` are forbidden here by contract.
///
/// ```compile_fail
/// use meissnerseal_security::audit_guard::AuditEventKind;
///
/// let kind = AuditEventKind::VaultUnlocked;
/// let _ = format!("{kind}");
/// ```
pub enum AuditEventKind {
    /// Vault was unlocked.
    VaultUnlocked,

    /// Vault was locked.
    VaultLocked,

    /// An item was accessed by identifier.
    ItemAccessed { item_id: AuditLabel },

    /// An item was created by identifier.
    ItemCreated { item_id: AuditLabel },

    /// An item was deleted by identifier.
    ItemDeleted { item_id: AuditLabel },

    /// A device was added by identifier.
    DeviceAdded { device_id: AuditLabel },

    /// A device was revoked by identifier.
    DeviceRevoked { device_id: AuditLabel },

    /// An export operation occurred.
    ExportPerformed,

    /// An import operation occurred.
    ImportPerformed,
}

impl core::fmt::Debug for AuditEventKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VaultUnlocked => f.write_str("AuditEventKind::VaultUnlocked"),
            Self::VaultLocked => f.write_str("AuditEventKind::VaultLocked"),
            Self::ItemAccessed { .. } => f.write_str("AuditEventKind::ItemAccessed([REDACTED])"),
            Self::ItemCreated { .. } => f.write_str("AuditEventKind::ItemCreated([REDACTED])"),
            Self::ItemDeleted { .. } => f.write_str("AuditEventKind::ItemDeleted([REDACTED])"),
            Self::DeviceAdded { .. } => f.write_str("AuditEventKind::DeviceAdded([REDACTED])"),
            Self::DeviceRevoked { .. } => f.write_str("AuditEventKind::DeviceRevoked([REDACTED])"),
            Self::ExportPerformed => f.write_str("AuditEventKind::ExportPerformed"),
            Self::ImportPerformed => f.write_str("AuditEventKind::ImportPerformed"),
        }
    }
}

/// Non-secret audit event.
pub struct AuditEvent {
    /// Event kind containing only non-secret identifiers.
    pub kind: AuditEventKind,

    /// Event timestamp in milliseconds.
    pub timestamp_ms: u64,

    /// Non-secret device identifier.
    pub device_id: AuditLabel,
}

/// Emit a non-secret audit event to the caller-managed audit pipeline.
///
/// # Contract
/// ## Preconditions
/// - `event` contains only non-secret operational metadata:
///   `item_id`, `device_id`, and `timestamp_ms`.
/// - Callers must never place item values, key material, passwords, recovery
///   material, `SecretBytes`, or `SecretString` in audit fields.
/// ## Postconditions
/// - Emits a structured event for caller-managed handling.
/// - Does not write to disk, network, or external logging systems directly.
/// ## Invariants
/// - `AuditEvent` has no fields capable of directly storing secret wrapper
///   types or raw key material.
/// - The audit guard never formats or logs secret values.
pub fn emit(_event: &AuditEvent) {}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn lbl(s: &str) -> AuditLabel {
        AuditLabel::try_from(s).expect("valid label in test fixture")
    }

    #[test]
    fn test_audit_event_has_no_secret_fields() {
        let kinds = [
            AuditEventKind::VaultUnlocked,
            AuditEventKind::VaultLocked,
            AuditEventKind::ItemAccessed {
                item_id: lbl("item-1"),
            },
            AuditEventKind::ItemCreated {
                item_id: lbl("item-2"),
            },
            AuditEventKind::ItemDeleted {
                item_id: lbl("item-3"),
            },
            AuditEventKind::DeviceAdded {
                device_id: lbl("device-1"),
            },
            AuditEventKind::DeviceRevoked {
                device_id: lbl("device-2"),
            },
            AuditEventKind::ExportPerformed,
            AuditEventKind::ImportPerformed,
        ];

        for kind in kinds {
            let _event = AuditEvent {
                kind,
                timestamp_ms: 1,
                device_id: lbl("device-local"),
            };
        }
    }

    #[test]
    fn test_emit_does_not_panic() {
        let event = AuditEvent {
            kind: AuditEventKind::VaultUnlocked,
            timestamp_ms: 1,
            device_id: lbl("device-local"),
        };

        emit(&event);
    }

    #[test]
    fn audit_event_kind_debug_redacts_identifier_strings() {
        let item_id = "vault-item-123";
        let kind = AuditEventKind::ItemAccessed {
            item_id: lbl(item_id),
        };
        let rendered = format!("{kind:?}");

        assert_eq!(rendered, "AuditEventKind::ItemAccessed([REDACTED])");
        assert!(!rendered.contains(item_id));

        let device_id = "vault-device-456";
        let kind = AuditEventKind::DeviceAdded {
            device_id: lbl(device_id),
        };
        let rendered = format!("{kind:?}");

        assert_eq!(rendered, "AuditEventKind::DeviceAdded([REDACTED])");
        assert!(!rendered.contains(device_id));
    }

    fn assert_audit_safe<T: AuditSafe>(_: &T) {}

    #[test]
    fn audit_event_kind_all_fields_are_audit_safe() {
        let id = lbl("test-id");
        let kinds = [
            AuditEventKind::VaultUnlocked,
            AuditEventKind::VaultLocked,
            AuditEventKind::ItemAccessed {
                item_id: id.clone(),
            },
            AuditEventKind::ItemCreated {
                item_id: id.clone(),
            },
            AuditEventKind::ItemDeleted {
                item_id: id.clone(),
            },
            AuditEventKind::DeviceAdded {
                device_id: id.clone(),
            },
            AuditEventKind::DeviceRevoked {
                device_id: id.clone(),
            },
            AuditEventKind::ExportPerformed,
            AuditEventKind::ImportPerformed,
        ];
        for kind in &kinds {
            match kind {
                AuditEventKind::ItemAccessed { item_id } => assert_audit_safe(item_id),
                AuditEventKind::ItemCreated { item_id } => assert_audit_safe(item_id),
                AuditEventKind::ItemDeleted { item_id } => assert_audit_safe(item_id),
                AuditEventKind::DeviceAdded { device_id } => assert_audit_safe(device_id),
                AuditEventKind::DeviceRevoked { device_id } => assert_audit_safe(device_id),
                AuditEventKind::VaultUnlocked
                | AuditEventKind::VaultLocked
                | AuditEventKind::ExportPerformed
                | AuditEventKind::ImportPerformed => {}
            }
        }
    }

    #[test]
    fn audit_label_rejects_empty_and_invalid_chars() {
        assert!(AuditLabel::try_from("valid-label:123").is_ok());
        assert!(AuditLabel::try_from("a b").is_err());
        assert!(AuditLabel::try_from("label!").is_err());
        assert!(AuditLabel::try_from(&"x".repeat(129) as &str).is_err());
        assert!(AuditLabel::try_from(&"x".repeat(128) as &str).is_ok());
    }
}
