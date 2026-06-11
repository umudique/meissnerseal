// SPDX-License-Identifier: Apache-2.0
//! Audit event contracts.
//!
/// Non-secret audit event kind.
pub enum AuditEventKind {
    /// Vault was unlocked.
    VaultUnlocked,

    /// Vault was locked.
    VaultLocked,

    /// An item was accessed by identifier.
    ItemAccessed { item_id: String },

    /// An item was created by identifier.
    ItemCreated { item_id: String },

    /// An item was deleted by identifier.
    ItemDeleted { item_id: String },

    /// A device was added by identifier.
    DeviceAdded { device_id: String },

    /// A device was revoked by identifier.
    DeviceRevoked { device_id: String },

    /// An export operation occurred.
    ExportPerformed,

    /// An import operation occurred.
    ImportPerformed,
}

/// Non-secret audit event.
pub struct AuditEvent {
    /// Event kind containing only non-secret identifiers.
    pub kind: AuditEventKind,

    /// Event timestamp in milliseconds.
    pub timestamp_ms: u64,

    /// Non-secret device identifier.
    pub device_id: String,
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
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_has_no_secret_fields() {
        let kinds = [
            AuditEventKind::VaultUnlocked,
            AuditEventKind::VaultLocked,
            AuditEventKind::ItemAccessed {
                item_id: String::from("item-1"),
            },
            AuditEventKind::ItemCreated {
                item_id: String::from("item-2"),
            },
            AuditEventKind::ItemDeleted {
                item_id: String::from("item-3"),
            },
            AuditEventKind::DeviceAdded {
                device_id: String::from("device-1"),
            },
            AuditEventKind::DeviceRevoked {
                device_id: String::from("device-2"),
            },
            AuditEventKind::ExportPerformed,
            AuditEventKind::ImportPerformed,
        ];

        for kind in kinds {
            let _event = AuditEvent {
                kind,
                timestamp_ms: 1,
                device_id: String::from("device-local"),
            };
        }
    }

    #[test]
    fn test_emit_does_not_panic() {
        let event = AuditEvent {
            kind: AuditEventKind::VaultUnlocked,
            timestamp_ms: 1,
            device_id: String::from("device-local"),
        };

        emit(&event);
    }
}
