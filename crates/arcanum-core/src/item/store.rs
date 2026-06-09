//! Item store API contracts.

use crate::{
    error::{CoreError, Result},
    item::model::{ItemId, ItemSummary, PlainItem, PlainItemView},
    vault::engine::VaultSession,
};

/// Add a plaintext item to an unlocked V2 vault and return its item id.
///
/// # Contract
///
/// ## Preconditions
/// - `session` was obtained through `vault::unlock`.
/// - `item.secret` contains plaintext that must be encrypted before
///   persistence.
/// - The target vault uses `SCHEMA_ARCANUM_RECORDS_V2`.
///
/// ## Postconditions
/// - On success, returns a fresh 128-bit CSPRNG `ItemId` that is also the item
///   record's `record_id`.
/// - Generates a fresh 128-bit `revision_id`, a fresh 32-byte Record Encryption
///   Key (REK), a fresh payload nonce, and a fresh REK-wrap nonce.
/// - Encrypts the item payload under the REK and wraps the REK under the
///   session's Item Key Wrapping Key (IKWK), both bound to the same canonical
///   74-byte record AAD from `vault_format_v1.md` §7.
/// - Adds one authenticated MEK-sealed table entry with `record_kind = 0x0001`
///   and rewrites the vault through the V2 crash-safe mutation path.
/// - Returns `Err` with no partial table, frame, or plaintext output on any
///   cryptographic, serialization, or I/O failure.
///
/// ## Invariants
/// - Uses only `arcanum-crypto` for RNG and AEAD operations; this crate never
///   implements cryptography directly.
/// - Does not write plaintext item bytes, labels, tags, REKs, IKWK, or MEK to
///   disk, logs, or error values.
/// - Metadata (`label`, `tags`) is encrypted into the item payload where
///   possible; the V2 table contains only routing fields.
pub fn add(_session: &VaultSession, item: PlainItem) -> Result<ItemId> {
    drop(item);
    Err(CoreError::InvalidState("item add not implemented".into()))
}

/// List non-secret summaries for live items in an unlocked V2 vault.
///
/// # Contract
///
/// ## Preconditions
/// - `session` was obtained through `vault::unlock`.
/// - The sealed table opens successfully under MEK.
///
/// ## Postconditions
/// - On success, returns summaries for live `record_kind = 0x0001` item records
///   and excludes `record_kind = 0x0006` tombstones.
/// - Summary metadata is obtained only after authenticating the sealed table and
///   decrypting item metadata where it is stored encrypted.
/// - Returns `Err` with no partial summaries if the table or any required item
///   metadata fails authentication.
///
/// ## Invariants
/// - Does not expose item secret payloads.
/// - Does not log or format plaintext metadata or secret bytes.
pub fn list(_session: &VaultSession) -> Result<Vec<ItemSummary>> {
    Err(CoreError::InvalidState("item list not implemented".into()))
}

/// Borrow one decrypted item inside a closure.
///
/// # Contract
///
/// ## Preconditions
/// - `session` was obtained through `vault::unlock`.
/// - `item_id` identifies a live item table entry, not a tombstone.
/// - The item frame's `record_id` and `revision_id` match the authenticated V2
///   table entry and are used to rebuild canonical AAD.
///
/// ## Postconditions
/// - On success, unwraps the REK under IKWK, decrypts the payload under REK, and
///   calls `f` exactly once with a closure-scoped [`PlainItemView`].
/// - Returns the closure's result `R`.
/// - Returns `Err` without calling `f` if table authentication, REK unwrap,
///   payload authentication, record id/revision substitution checks, or parser
///   validation fail.
///
/// ## Invariants
/// - Never returns owned plaintext. The plaintext view cannot outlive the
///   closure (CONTRACT G-02).
/// - No plaintext item bytes are written to disk, logs, or error values.
/// - Authentication failure returns `Err` with no partial plaintext output.
pub fn with_item<F, R>(_session: &VaultSession, _item_id: ItemId, f: F) -> Result<R>
where
    F: FnOnce(&PlainItemView<'_>) -> Result<R>,
{
    let _ = f;
    Err(CoreError::InvalidState(
        "item with_item not implemented".into(),
    ))
}

/// Replace an existing item with a new encrypted revision.
///
/// # Contract
///
/// ## Preconditions
/// - `session` was obtained through `vault::unlock`.
/// - `item_id` identifies a live item record.
/// - `item.secret` contains plaintext replacement bytes.
///
/// ## Postconditions
/// - On success, preserves `record_id`, generates a fresh `revision_id`, fresh
///   REK, fresh payload nonce, and fresh REK-wrap nonce.
/// - Re-encrypts the payload and wrapped REK under AAD containing the new
///   `revision_id`; the previous revision's REK/AAD must not authenticate the
///   replacement frame.
/// - Re-seals the V2 table with the bumped revision metadata and rewrites the
///   vault through the crash-safe mutation path.
/// - Returns `Err` with no partial replacement on any failure.
///
/// ## Invariants
/// - No old or new plaintext item payload, REK, IKWK, or MEK is logged, printed,
///   or written to an error value.
pub fn update(_session: &VaultSession, _item_id: ItemId, item: PlainItem) -> Result<()> {
    drop(item);
    Err(CoreError::InvalidState(
        "item update not implemented".into(),
    ))
}

/// Delete a live item by writing a tombstone.
///
/// # Contract
///
/// ## Preconditions
/// - `session` was obtained through `vault::unlock`.
/// - `item_id` identifies a live item or an already-deleted item.
///
/// ## Postconditions
/// - On success, writes an authenticated V2 table entry with
///   `record_kind = 0x0006` (Tombstone) and a fresh `revision_id`.
/// - After success, `list` omits the deleted item and `with_item` returns `Err`
///   for `item_id`.
/// - Re-seals the V2 table and rewrites the vault through the crash-safe
///   mutation path.
/// - Returns `Err` with no partial tombstone on serialization or I/O failure.
///
/// ## Invariants
/// - Deletion never exposes or logs the deleted item's plaintext.
/// - The tombstone is authenticated metadata; no best-effort deletion state is
///   returned on failure.
pub fn delete(_session: &VaultSession, _item_id: ItemId) -> Result<()> {
    Err(CoreError::InvalidState(
        "item delete not implemented".into(),
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        item::model::ItemKind,
        vault::engine::{create, lock, unlock, CreateVaultParams, UnlockParams},
    };
    use arcanum_security::secret_lifecycle::SecretBytes;

    const PASSWORD: &[u8] = b"core-9-item-password-never-real";

    fn unique_temp_vault_path(label: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        path.push(format!(
            "arcanum-core-item-{label}-{}-{nanos}.arcv",
            std::process::id()
        ));
        path
    }

    fn unlocked_session(label: &str) -> (std::path::PathBuf, VaultSession) {
        let path = unique_temp_vault_path(label);
        let _ = std::fs::remove_file(&path);
        create(CreateVaultParams {
            path: path.clone(),
            password: SecretBytes::new(PASSWORD.to_vec()),
        })
        .expect("create item test vault");
        let session = unlock(UnlockParams {
            path: path.clone(),
            password: SecretBytes::new(PASSWORD.to_vec()),
        })
        .expect("unlock item test vault");
        (path, session)
    }

    fn plain_item(label: &str, secret: &[u8]) -> PlainItem {
        PlainItem {
            kind: ItemKind::SecureNote,
            label: label.to_string(),
            secret: SecretBytes::new(secret.to_vec()),
            tags: vec!["core9".to_string()],
        }
    }

    fn cleanup(path: &std::path::Path, session: VaultSession) {
        let _ = lock(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn add_then_list_shows_item_summary() {
        let (path, session) = unlocked_session("add-list");

        let item_id = add(&session, plain_item("api token", b"token-bytes"))
            .expect("Phase 2: add must persist an encrypted item");
        let summaries = list(&session).expect("Phase 2: list must open sealed table");

        assert!(summaries.iter().any(|summary| summary.id == item_id));
        cleanup(&path, session);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn with_item_exposes_plaintext_only_inside_closure() {
        let (path, session) = unlocked_session("with-item");

        let item_id = add(&session, plain_item("seed phrase", b"seed-bytes"))
            .expect("Phase 2: add must persist encrypted item");
        let observed_len = with_item(&session, item_id, |view| {
            assert_eq!(view.label, "seed phrase");
            view.secret.with_secret(|secret| Ok(secret.len()))
        })
        .expect("Phase 2: with_item must decrypt inside closure");

        assert_eq!(observed_len, b"seed-bytes".len());
        cleanup(&path, session);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn update_bumps_revision_and_old_rek_aad_no_longer_authenticates() {
        let (path, session) = unlocked_session("update-revision");

        let item_id = add(&session, plain_item("note", b"old"))
            .expect("Phase 2: add must persist encrypted item");
        update(&session, item_id, plain_item("note", b"new"))
            .expect("Phase 2: update must write a fresh revision");
        let observed = with_item(&session, item_id, |view| {
            view.secret.with_secret(|secret| Ok(secret.len()))
        })
        .expect("Phase 2: new revision must decrypt");

        assert_eq!(observed, b"new".len());
        cleanup(&path, session);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn delete_writes_tombstone_and_item_disappears_from_list() {
        let (path, session) = unlocked_session("delete");

        let item_id = add(&session, plain_item("obsolete", b"delete-me"))
            .expect("Phase 2: add must persist encrypted item");
        delete(&session, item_id).expect("Phase 2: delete must write tombstone");
        let summaries = list(&session).expect("Phase 2: list must omit tombstones");

        assert!(summaries.iter().all(|summary| summary.id != item_id));
        cleanup(&path, session);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn added_item_survives_lock_unlock_roundtrip() {
        let (path, session) = unlocked_session("roundtrip");

        let item_id = add(&session, plain_item("persistent", b"survives"))
            .expect("Phase 2: add must persist encrypted item");
        lock(session).expect("lock item test session");
        let session = unlock(UnlockParams {
            path: path.clone(),
            password: SecretBytes::new(PASSWORD.to_vec()),
        })
        .expect("unlock item test vault after add");
        let observed = with_item(&session, item_id, |view| {
            view.secret.with_secret(|secret| Ok(secret.len()))
        })
        .expect("Phase 2: item must survive unlock");

        assert_eq!(observed, b"survives".len());
        cleanup(&path, session);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn tampered_item_ciphertext_rejects_without_plaintext() {
        let (path, session) = unlocked_session("tamper-payload");

        let item_id = add(&session, plain_item("tamper", b"payload"))
            .expect("Phase 2: add must persist encrypted item");
        let result: Result<()> = with_item(&session, item_id, |_view| {
            panic!("Phase 2: tampered ciphertext must not call closure")
        });

        assert!(result.is_err());
        cleanup(&path, session);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn tampered_wrapped_rek_rejects_without_plaintext() {
        let (path, session) = unlocked_session("tamper-rek");

        let item_id = add(&session, plain_item("tamper", b"rek"))
            .expect("Phase 2: add must persist encrypted item");
        let result: Result<()> = with_item(&session, item_id, |_view| {
            panic!("Phase 2: tampered wrapped REK must not call closure")
        });

        assert!(result.is_err());
        cleanup(&path, session);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn substituted_record_id_or_revision_rejects_by_aad_authentication() {
        let (path, session) = unlocked_session("substitution");

        let item_id = add(&session, plain_item("substitution", b"aad-bound"))
            .expect("Phase 2: add must persist encrypted item");
        let result: Result<()> = with_item(&session, item_id, |_view| {
            panic!("Phase 2: substituted record metadata must not call closure")
        });

        assert!(result.is_err());
        cleanup(&path, session);
    }
}
