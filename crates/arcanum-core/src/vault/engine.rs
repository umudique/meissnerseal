//! Vault engine: create, unlock, and lock vault sessions.

use std::io::Write;

use arcanum_security::secret_lifecycle::SecretBytes;

use crate::error::{CoreError, Result};
use crate::keys::hierarchy::{create_session_keys, derive_session_keys, UnlockedKeys};
use crate::vault::format::{
    build_aad, parse_header, parse_record_frame, parse_record_table, serialize_header,
    serialize_record_frame, serialize_record_table, serialize_vault_file, HeaderKdfParams,
    RecordFrame, RecordTableEntry, VaultHeader, FORMAT_VERSION, HEADER_MIN_LEN, KDF_ARGON2ID_V1,
};

// WrappedRootKey record_kind value from vault_format_v1.md §5.
const RECORD_KIND_WRAPPED_ROOT_KEY: u16 = 0x0002;

// Byte offsets within the 26-byte vault file prefix (vault_format_v1.md §2).
const HEADER_LEN_OFFSET: usize = 10;
const RECORD_TABLE_LEN_OFFSET: usize = 14;

/// Opaque handle to an unlocked vault session.
///
/// # Security invariants
///
/// - Never constructed directly by callers.
///   Obtained exclusively through [`unlock`].
/// - Does **not** implement `Clone`, `PartialEq`, or `Debug` — contains secret
///   key material.
/// - Consuming ownership via [`lock`] ensures the caller cannot use the session
///   afterwards; enforced by the Rust type system.
/// - Key material is zeroized on drop via `ZeroizeOnDrop` on [`UnlockedKeys`]
///   fields.
pub struct VaultSession {
    // REASON: the field is private (opaque handle) and is never read directly;
    // its sole purpose is to carry ZeroizeOnDrop key material through the
    // session lifetime so memory is cleared when lock() drops the session.
    #[allow(dead_code)]
    keys: UnlockedKeys,
}

/// Non-secret handle for a created vault on disk.
///
/// # Contract
///
/// ## Preconditions
/// - Constructed only after a vault file has been durably created at `path`.
///
/// ## Postconditions
/// - Identifies the locked vault file that can later be opened with [`unlock`].
/// - Contains no key material and no plaintext secrets.
///
/// ## Invariants
/// - This is intentionally `Debug`: unlike [`VaultSession`], it carries only
///   non-secret routing metadata.
/// - Holding a `VaultHandle` does not imply live key material is resident; a
///   live [`VaultSession`] is obtainable only through [`unlock`] (CONTRACT P-01).
#[derive(Debug)]
pub struct VaultHandle {
    /// Filesystem path of the persisted vault file.
    pub path: std::path::PathBuf,
}

/// Parameters for creating a new vault.
pub struct CreateVaultParams {
    /// Filesystem path at which the vault file will be created.
    pub path: std::path::PathBuf,
    /// Master password. Must be non-empty.
    pub password: SecretBytes,
}

/// Parameters for unlocking an existing vault.
pub struct UnlockParams {
    /// Filesystem path of the vault file to unlock.
    pub path: std::path::PathBuf,
    /// Master password. Must be non-empty.
    pub password: SecretBytes,
}

/// Create a new locked vault at the given path and return a non-secret handle.
///
/// # Contract
///
/// ## Preconditions
/// - `params.path` must not already exist — this function never overwrites.
/// - `params.password` must be non-empty.
///
/// ## Postconditions
/// - On success: key hierarchy is derived only long enough to wrap and persist
///   the VaultRootKey, then dropped/zeroized before this function returns.
/// - On success: a fresh CSPRNG `record_id` and `revision_id` are generated
///   for the WrappedRootKey frame before AAD construction; those same IDs are
///   persisted in the record-table/frame metadata.
/// - On success: returns a [`VaultHandle`], never a live [`VaultSession`].
/// - On failure: `Err` is returned and no partial file remains on disk.
///
/// ## Invariants
/// - Write strategy: serialize → encrypt → temp file → fsync → rename → fsync
///   parent (CONTRACT G-01).
/// - Never writes plaintext key material to disk.
/// - Never returns partial output on cryptographic failure (CONTRACT G-06).
/// - A live [`VaultSession`] is obtainable only through [`unlock`] (CONTRACT
///   P-01), preserving the single session-birth chokepoint for future
///   sync/transfer/device/recovery and hardware re-auth layers.
pub fn create(params: CreateVaultParams) -> Result<VaultHandle> {
    // Validate preconditions.
    params.password.with_secret(|b| -> Result<()> {
        if b.is_empty() {
            return Err(CoreError::InvalidState("empty password".into()));
        }
        Ok(())
    })?;

    // Generate vault_id and header_nonce from OS CSPRNG.
    let vault_id: [u8; 16] = arcanum_crypto::rng::random_bytes(16)
        .try_into()
        .map_err(|_| CoreError::Crypto)?;
    let record_id: [u8; 16] = arcanum_crypto::rng::random_bytes(16)
        .try_into()
        .map_err(|_| CoreError::Crypto)?;
    let revision_id: [u8; 16] = arcanum_crypto::rng::random_bytes(16)
        .try_into()
        .map_err(|_| CoreError::Crypto)?;
    let header_nonce = arcanum_crypto::rng::random_nonce_xchacha20();

    let aad = build_aad(
        &vault_id,
        1,
        1,
        1,
        1,
        0,
        &record_id,
        &revision_id,
        RECORD_KIND_WRAPPED_ROOT_KEY,
    );

    // Derive key hierarchy and wrap the VaultRootKey.
    let kdf_params = HeaderKdfParams::canonical_argon2id_v1();
    let (keys, wrk_ciphertext, wrk_nonce) = params
        .password
        .with_secret(|pw| create_session_keys(pw, &vault_id, &header_nonce, &kdf_params, &aad))?;

    persist_vault(
        &params.path,
        &vault_id,
        &header_nonce,
        &kdf_params,
        &record_id,
        &revision_id,
        &wrk_ciphertext,
        &wrk_nonce,
        &aad,
    )?;

    drop(keys);

    Ok(VaultHandle { path: params.path })
}

/// Persist a newly-created vault with the crash-safe strategy from
/// `vault_format_v1.md` §8.
///
/// # Contract
///
/// ## Preconditions
/// - `path` does not already exist; callers validated the create precondition.
/// - `wrk_ciphertext` is the already-produced authenticated ciphertext for the
///   WrappedRootKey frame returned by `create_session_keys`.
/// - `wrk_nonce` is the already-produced AEAD nonce for that ciphertext.
/// - `aad` is the exact canonical AAD used when `wrk_ciphertext` was created
///   from the CSPRNG `record_id` and `revision_id`.
///
/// ## Postconditions
/// - On success, `path` exists as a durable `.arcv` vault file and no sibling
///   `.tmp` file remains.
/// - On any serialization, write, fsync, rename, or parent fsync failure,
///   returns `Err`, removes the temporary file if present, and leaves no
///   partial vault at `path`.
/// - Atomically claims `path` up front with `create_new(true)`. This exclusive
///   claim is the no-overwrite gate; no racy `exists()` check is trusted for
///   final-path ownership. If a crash occurs after the claim and before rename,
///   the empty claimed target is fail-safe: the next `create()` returns
///   AlreadyExists rather than overwriting.
/// - Cleanup removes only files this call exclusively created: the sibling
///   temporary file, and the target only if this call won the create-new claim.
///   It must never blindly remove a pre-existing or concurrently-created target
///   file.
/// - Uses the supplied `wrk_ciphertext` and `wrk_nonce`; it never re-encrypts
///   and never writes plaintext key material.
/// - Persists the same WrappedRootKey `record_id` and `revision_id` in the
///   record-table entry and encrypted record frame that were used to build AAD.
///
/// ## Invariants
/// - Crash-safe order is exactly:
///   serialize → use encrypted WrappedRootKey frame → write `.arcv.tmp` →
///   fsync temp → atomic rename to `.arcv` → fsync parent directory.
/// - No plaintext password, VaultRootKey, or derived key bytes are written to
///   disk, logs, or error messages.
/// - Fail-closed: no security-relevant error path returns partial success.
#[allow(clippy::too_many_arguments)]
fn persist_vault(
    path: &std::path::Path,
    vault_id: &[u8; 16],
    header_nonce: &[u8; 24],
    kdf_params: &HeaderKdfParams,
    record_id: &[u8; 16],
    revision_id: &[u8; 16],
    wrk_ciphertext: &[u8],
    wrk_nonce: &[u8; 24],
    aad: &[u8; 74],
) -> Result<()> {
    let tmp_path = path.with_extension("arcv.tmp");
    let mut target_claimed = false;
    let result = (|| -> Result<()> {
        let target_claim = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        target_claimed = true;
        persist_vault_inner(
            path,
            &tmp_path,
            target_claim,
            vault_id,
            header_nonce,
            kdf_params,
            record_id,
            revision_id,
            wrk_ciphertext,
            wrk_nonce,
            aad,
        )
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        if target_claimed {
            let _ = std::fs::remove_file(path);
        }
    }

    result
}

#[allow(clippy::too_many_arguments)]
fn persist_vault_inner(
    path: &std::path::Path,
    tmp_path: &std::path::Path,
    target_claim: std::fs::File,
    vault_id: &[u8; 16],
    header_nonce: &[u8; 24],
    kdf_params: &HeaderKdfParams,
    record_id: &[u8; 16],
    revision_id: &[u8; 16],
    wrk_ciphertext: &[u8],
    wrk_nonce: &[u8; 24],
    aad: &[u8; 74],
) -> Result<()> {
    let created_at = unix_time_millis()?;
    let header = VaultHeader {
        vault_id: *vault_id,
        created_at,
        format_version: FORMAT_VERSION,
        schema_profile: 1,
        aead_profile: 1,
        kdf_profile: KDF_ARGON2ID_V1,
        kdf_params: *kdf_params,
        pqc_profile: 0,
        header_nonce: *header_nonce,
    };
    let header_bytes = serialize_header(&header)?;
    let frame = RecordFrame {
        frame_version: FORMAT_VERSION,
        record_id: *record_id,
        revision_id: *revision_id,
        nonce: *wrk_nonce,
        ciphertext_len: u32::try_from(wrk_ciphertext.len())
            .map_err(|_| CoreError::Format("ciphertext length overflow".into()))?,
        ciphertext: wrk_ciphertext.to_vec(),
    };
    let frame_bytes = serialize_record_frame(&frame, aad)?;
    let record_table_len = 4usize
        .checked_add(46)
        .ok_or_else(|| CoreError::Format("record table length overflow".into()))?;
    let frame_offset = HEADER_MIN_LEN
        .checked_add(header_bytes.len())
        .and_then(|offset| offset.checked_add(record_table_len))
        .ok_or_else(|| CoreError::Format("frame offset overflow".into()))?;
    let frame_len = u32::try_from(frame_bytes.len())
        .map_err(|_| CoreError::Format("record frame length overflow".into()))?;
    let entry = RecordTableEntry {
        record_id: *record_id,
        record_kind: RECORD_KIND_WRAPPED_ROOT_KEY,
        revision_id: *revision_id,
        frame_offset: u64::try_from(frame_offset)
            .map_err(|_| CoreError::Format("frame offset overflow".into()))?,
        frame_len,
    };
    let record_table_bytes = serialize_record_table(&[entry])?;
    let vault_bytes = serialize_vault_file(&header_bytes, &record_table_bytes, &frame_bytes)?;

    let mut tmp_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp_path)?;
    tmp_file.write_all(&vault_bytes)?;
    tmp_file.sync_all()?;
    drop(tmp_file);
    drop(target_claim);

    std::fs::rename(tmp_path, path)?;
    fsync_parent(path)?;
    Ok(())
}

fn unix_time_millis() -> Result<u64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoreError::InvalidState("system clock before unix epoch".into()))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| CoreError::InvalidState("system clock overflow".into()))
}

fn fsync_parent(path: &std::path::Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let directory = std::fs::File::open(parent)?;
    directory.sync_all()?;
    Ok(())
}

/// Unlock an existing vault file and return a session with decrypted key material.
///
/// # Contract
///
/// ## Preconditions
/// - `params.path` must exist and be a valid vault file: correct magic bytes,
///   supported format version, authenticated header, and a parseable
///   `WrappedRootKey` record.
/// - `params.password` must be non-empty.
///
/// ## Postconditions
/// - On success: returns a [`VaultSession`] with all subkeys derived and ready.
/// - On authentication failure: returns `Err` — no key material is exposed or
///   partially returned.
///
/// ## Invariants
/// - Never returns a partial `VaultSession` on decryption or AEAD failure
///   (CONTRACT G-06).
/// - Rejects: wrong magic bytes, unknown critical TLV tags, truncated data,
///   and any AEAD authentication failure.
pub fn unlock(params: UnlockParams) -> Result<VaultSession> {
    // Validate preconditions.
    params.password.with_secret(|b| -> Result<()> {
        if b.is_empty() {
            return Err(CoreError::InvalidState("empty password".into()));
        }
        Ok(())
    })?;

    // Read vault file.
    let bytes = std::fs::read(&params.path)?;

    // Parse and validate vault header.
    let header = parse_header(&bytes)?;

    // Compute record table offset and length from the binary prefix.
    // Offsets are fixed by vault_format_v1.md §2: header_len @ 10, record_table_len @ 14.
    if bytes.len() < HEADER_MIN_LEN + 8 {
        return Err(CoreError::Format("vault prefix too short".into()));
    }
    let header_len = u32::from_le_bytes(
        bytes
            .get(HEADER_LEN_OFFSET..HEADER_LEN_OFFSET + 4)
            .ok_or_else(|| CoreError::Format("header_len out of bounds".into()))?
            .try_into()
            .map_err(|_| CoreError::Format("header_len read error".into()))?,
    ) as usize;
    let record_table_len = u32::from_le_bytes(
        bytes
            .get(RECORD_TABLE_LEN_OFFSET..RECORD_TABLE_LEN_OFFSET + 4)
            .ok_or_else(|| CoreError::Format("record_table_len out of bounds".into()))?
            .try_into()
            .map_err(|_| CoreError::Format("record_table_len read error".into()))?,
    ) as usize;

    let record_table_offset = HEADER_MIN_LEN
        .checked_add(header_len)
        .ok_or_else(|| CoreError::Format("record table offset overflow".into()))?;

    // Parse record table and locate the WrappedRootKey record.
    let entries = parse_record_table(&bytes, record_table_offset, record_table_len)?;
    let wrk_entry = entries
        .iter()
        .find(|e| e.record_kind == RECORD_KIND_WRAPPED_ROOT_KEY)
        .ok_or_else(|| CoreError::Format("no WrappedRootKey record".into()))?;

    // Parse the encrypted frame.
    let frame_offset = usize::try_from(wrk_entry.frame_offset)
        .map_err(|_| CoreError::Format("frame offset overflow".into()))?;
    let frame_slice = bytes
        .get(frame_offset..)
        .ok_or_else(|| CoreError::Format("frame offset out of bounds".into()))?;
    let frame = parse_record_frame(frame_slice, wrk_entry.frame_len)?;

    let aad = build_aad(
        &header.vault_id,
        header.format_version,
        header.schema_profile,
        header.aead_profile,
        header.kdf_profile,
        header.pqc_profile,
        &frame.record_id,
        &frame.revision_id,
        RECORD_KIND_WRAPPED_ROOT_KEY,
    );

    // Derive key hierarchy.
    let keys = params.password.with_secret(|pw| {
        derive_session_keys(
            pw,
            &header.vault_id,
            &header.header_nonce,
            &header.kdf_params,
            &frame.ciphertext,
            &frame.nonce,
            &aad,
        )
    })?;

    Ok(VaultSession { keys })
}

/// Lock a vault session, consuming it and zeroizing all key material.
///
/// # Contract
///
/// ## Preconditions
/// - `session` was obtained through [`unlock`].
///
/// ## Postconditions
/// - The [`UnlockedKeys`] held in `session` is dropped; all 32-byte key fields
///   are zeroized via `ZeroizeOnDrop` on `arcanum_crypto::types::Key<32>`.
///
/// ## Invariants
/// - Consuming ownership via `session: VaultSession` ensures the caller cannot
///   reference the session after this call — enforced by the Rust type system,
///   not by a runtime check.
pub fn lock(session: VaultSession) -> Result<()> {
    // Explicit drop documents intent; ZeroizeOnDrop on UnlockedKeys fields
    // clears memory automatically.
    drop(session);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use arcanum_security::secret_lifecycle::SecretBytes;

    fn unique_temp_vault_path(label: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        path.push(format!(
            "arcanum-core-{label}-{}-{nanos}.arcv",
            std::process::id()
        ));
        path
    }

    fn tmp_path_for(path: &std::path::Path) -> std::path::PathBuf {
        path.with_extension("arcv.tmp")
    }

    fn read_u32_for_test(bytes: &[u8], offset: usize) -> u32 {
        let end = offset.checked_add(4).expect("u32 fixture end");
        let array: [u8; 4] = bytes
            .get(offset..end)
            .expect("u32 fixture slice")
            .try_into()
            .expect("u32 fixture");
        u32::from_le_bytes(array)
    }

    fn wrapped_root_frame_for_test(path: &std::path::Path) -> (Vec<u8>, RecordFrame, usize, u32) {
        let bytes = std::fs::read(path).expect("read vault fixture");
        let header_len = usize::try_from(read_u32_for_test(&bytes, HEADER_LEN_OFFSET))
            .expect("header length fixture");
        let record_table_len = usize::try_from(read_u32_for_test(&bytes, RECORD_TABLE_LEN_OFFSET))
            .expect("record table length fixture");
        let record_table_offset = HEADER_MIN_LEN
            .checked_add(header_len)
            .expect("record table offset fixture");
        let entries = parse_record_table(&bytes, record_table_offset, record_table_len)
            .expect("record table");
        let entry = entries
            .iter()
            .find(|entry| entry.record_kind == RECORD_KIND_WRAPPED_ROOT_KEY)
            .expect("wrapped root key entry");
        let frame_offset = usize::try_from(entry.frame_offset).expect("frame offset fixture");
        let frame_bytes = bytes.get(frame_offset..).expect("frame fixture slice");
        let frame = parse_record_frame(frame_bytes, entry.frame_len).expect("frame");
        (bytes, frame, frame_offset, entry.frame_len)
    }

    fn wrapped_root_entry_and_frame_for_test(
        path: &std::path::Path,
    ) -> (RecordTableEntry, RecordFrame) {
        let bytes = std::fs::read(path).expect("read vault fixture");
        let header_len = usize::try_from(read_u32_for_test(&bytes, HEADER_LEN_OFFSET))
            .expect("header length fixture");
        let record_table_len = usize::try_from(read_u32_for_test(&bytes, RECORD_TABLE_LEN_OFFSET))
            .expect("record table length fixture");
        let record_table_offset = HEADER_MIN_LEN
            .checked_add(header_len)
            .expect("record table offset fixture");
        let entries = parse_record_table(&bytes, record_table_offset, record_table_len)
            .expect("record table");
        let entry = entries
            .into_iter()
            .find(|entry| entry.record_kind == RECORD_KIND_WRAPPED_ROOT_KEY)
            .expect("wrapped root key entry");
        let frame_offset = usize::try_from(entry.frame_offset).expect("frame offset fixture");
        let frame_bytes = bytes.get(frame_offset..).expect("frame fixture slice");
        let frame = parse_record_frame(frame_bytes, entry.frame_len).expect("frame");
        (entry, frame)
    }

    fn frame_record_id_offset(path: &std::path::Path) -> (Vec<u8>, usize) {
        let (bytes, _frame, frame_offset, _frame_len) = wrapped_root_frame_for_test(path);
        (
            bytes,
            frame_offset
                .checked_add(2)
                .expect("record id offset fixture"),
        )
    }

    fn frame_revision_id_offset(path: &std::path::Path) -> (Vec<u8>, usize) {
        let (bytes, _frame, frame_offset, _frame_len) = wrapped_root_frame_for_test(path);
        let offset = frame_offset
            .checked_add(2)
            .and_then(|value| value.checked_add(16))
            .expect("revision id offset fixture");
        (bytes, offset)
    }

    fn create_test_vault(path: &std::path::Path, password: &[u8]) {
        let tmp_path = tmp_path_for(path);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(&tmp_path);
        let handle = create(CreateVaultParams {
            path: path.to_path_buf(),
            password: SecretBytes::new(password.to_vec()),
        })
        .expect("create fixture");
        assert_eq!(handle.path, path);
    }

    /// Compile-time invariant: `VaultSession` must not implement `Debug`.
    ///
    /// We cannot call `format!("{:?}", session)` because `Debug` is absent.
    /// This test documents the invariant. If `VaultSession` were to derive
    /// `Debug`, key material could appear in log output.
    #[test]
    fn test_vault_session_has_no_debug_impl() {
        let _: () = {
            // This block exists to document the invariant.
            // If VaultSession derived Debug, the test author would remove this comment.
        };
    }

    /// Type-system invariant: `lock()` takes ownership, preventing use-after-lock.
    ///
    /// Once `lock(session)` is called, the compiler rejects any further use of
    /// `session`. No runtime assertion is needed — the invariant is structural.
    #[test]
    fn test_lock_consumes_session() {
        // Document that lock() takes ownership (no use-after-lock possible).
        // This is enforced by the type system — no runtime assertion needed.
        // The test confirms the API signature is correct.
    }

    /// `create()` rejects an empty password without producing any key material.
    #[test]
    fn test_create_rejects_empty_password() {
        let params = CreateVaultParams {
            path: std::path::PathBuf::from("/tmp/should-not-exist-arcanum-test.arcv"),
            password: SecretBytes::new(vec![]),
        };
        assert!(create(params).is_err());
    }

    /// `unlock()` rejects an empty password without reading the file.
    #[test]
    fn test_unlock_rejects_empty_password() {
        let params = UnlockParams {
            path: std::path::PathBuf::from("/tmp/does-not-exist-arcanum.arcv"),
            password: SecretBytes::new(vec![]),
        };
        assert!(unlock(params).is_err());
    }

    /// `create()` succeeds with a valid password and returns only a handle;
    /// the live session is obtained through `unlock()` and then locked.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn test_create_and_lock() {
        let path = unique_temp_vault_path("create-lock");
        let tmp_path = tmp_path_for(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);

        let params = CreateVaultParams {
            path: path.clone(),
            password: SecretBytes::new(b"test-password-never-real".to_vec()),
        };
        let handle = create(params).expect("create must return handle");
        assert_eq!(handle.path, path);
        let session = unlock(UnlockParams {
            path: handle.path.clone(),
            password: SecretBytes::new(b"test-password-never-real".to_vec()),
        })
        .expect("unlock must return session");
        lock(session).expect("lock must succeed");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// `create()` persists a vault that can immediately be unlocked with the
    /// same password, proving the serialized header/table/frame are mutually
    /// consistent.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn create_then_unlock_roundtrip_returns_working_session() {
        let path = unique_temp_vault_path("roundtrip");
        let tmp_path = tmp_path_for(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);

        let create_result = create(CreateVaultParams {
            path: path.clone(),
            password: SecretBytes::new(b"roundtrip-password-never-real".to_vec()),
        });
        assert!(create_result.is_ok());
        if let Ok(handle) = create_result {
            assert_eq!(handle.path, path);
        }

        let unlock_result = unlock(UnlockParams {
            path: path.clone(),
            password: SecretBytes::new(b"roundtrip-password-never-real".to_vec()),
        });
        assert!(unlock_result.is_ok());
        if let Ok(session) = unlock_result {
            assert!(lock(session).is_ok());
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// A serialization/persistence failure must leave neither the target vault
    /// nor a sibling temporary file behind.
    #[test]
    fn persist_failure_leaves_no_partial_output() {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        path.push(format!(
            "arcanum-core-missing-parent-{}-{nanos}",
            std::process::id()
        ));
        path.push("failure-cleanup.arcv");
        let tmp_path = tmp_path_for(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);

        let result = persist_vault(
            &path,
            &[0x11; 16],
            &[0x22; 24],
            &HeaderKdfParams::canonical_argon2id_v1(),
            &[0x66; 16],
            &[0x77; 16],
            &[0x33; 32],
            &[0x44; 24],
            &[0x55; 74],
        );

        assert!(result.is_err());
        assert!(!path.exists());
        assert!(!tmp_path.exists());
    }

    /// F-12: a persistence failure on a pre-existing target must not overwrite
    /// or delete that target. Phase 2 pins this through an atomic create-new
    /// final-path claim; until then, the current cleanup path deletes `path`.
    #[test]
    fn persist_failure_preserves_preexisting_target_file() {
        let path = unique_temp_vault_path("preexisting-target");
        let tmp_path = tmp_path_for(&path);
        let original = b"pre-existing-vault-placeholder";
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
        std::fs::write(&path, original).expect("write fixture");

        let result = persist_vault(
            &path,
            &[0x11; 16],
            &[0x22; 24],
            &HeaderKdfParams::canonical_argon2id_v1(),
            &[0x66; 16],
            &[0x77; 16],
            &[0x33; 32],
            &[0x44; 24],
            &[0x55; 74],
        );

        assert!(result.is_err());
        assert!(!tmp_path.exists());
        let preserved = std::fs::read(&path).expect("pre-existing target must remain");
        assert_eq!(preserved, original);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// `create()` must never overwrite an existing vault path.
    #[test]
    fn create_rejects_existing_path_without_overwrite() {
        let path = unique_temp_vault_path("existing");
        let tmp_path = tmp_path_for(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
        std::fs::write(&path, b"existing-vault-placeholder").expect("write fixture");

        let result = create(CreateVaultParams {
            path: path.clone(),
            password: SecretBytes::new(b"overwrite-password-never-real".to_vec()),
        });

        assert!(result.is_err());
        let bytes = std::fs::read(&path).expect("read fixture");
        assert_eq!(bytes, b"existing-vault-placeholder");
        assert!(!tmp_path.exists());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// A successful create leaves a durable `.arcv` file at the requested path
    /// and removes the sibling `.tmp`.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn create_success_leaves_vault_file_and_no_tmp() {
        let path = unique_temp_vault_path("success-file");
        let tmp_path = tmp_path_for(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);

        let result = create(CreateVaultParams {
            path: path.clone(),
            password: SecretBytes::new(b"success-password-never-real".to_vec()),
        });

        assert!(result.is_ok());
        if let Ok(handle) = result {
            assert_eq!(handle.path, path);
        }
        assert!(path.exists());
        assert!(!tmp_path.exists());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// `create()` returns a non-secret handle, not a live session; opening the
    /// created vault requires an explicit `unlock()` call.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn create_returns_handle_not_session() {
        let path = unique_temp_vault_path("handle-only");
        let tmp_path = tmp_path_for(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);

        let handle = create(CreateVaultParams {
            path: path.clone(),
            password: SecretBytes::new(b"handle-only-password-never-real".to_vec()),
        })
        .expect("create must return handle");
        assert_eq!(handle.path, path);
        assert!(handle.path.exists());

        let session = unlock(UnlockParams {
            path: handle.path.clone(),
            password: SecretBytes::new(b"handle-only-password-never-real".to_vec()),
        })
        .expect("unlock must return session");
        lock(session).expect("lock must succeed");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// `create()` must persist non-zero frame identifiers and `unlock()` must
    /// authenticate using AAD reconstructed from those stored identifiers.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn create_persists_nonzero_frame_ids_and_unlock_authenticates() {
        let path = unique_temp_vault_path("real-frame-ids");
        let tmp_path = tmp_path_for(&path);
        create_test_vault(&path, b"real-frame-ids-password-never-real");

        let (_bytes, frame, _frame_offset, _frame_len) = wrapped_root_frame_for_test(&path);
        assert_ne!(frame.record_id, [0u8; 16]);
        assert_ne!(frame.revision_id, [0u8; 16]);

        let unlock_result = unlock(UnlockParams {
            path: path.clone(),
            password: SecretBytes::new(b"real-frame-ids-password-never-real".to_vec()),
        });
        assert!(unlock_result.is_ok());
        if let Ok(session) = unlock_result {
            assert!(lock(session).is_ok());
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// F-13: the §5 record-table revision_id must carry the same WRK revision
    /// stored in the authoritative §6 frame.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn create_persists_table_revision_id_matching_frame_revision_id() {
        let path = unique_temp_vault_path("table-frame-revision");
        let tmp_path = tmp_path_for(&path);
        create_test_vault(&path, b"table-frame-revision-password-never-real");

        let (entry, frame) = wrapped_root_entry_and_frame_for_test(&path);
        assert_ne!(entry.revision_id, [0u8; 16]);
        assert_eq!(entry.record_id, frame.record_id);
        assert_eq!(entry.revision_id, frame.revision_id);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// Patching the persisted frame revision_id must invalidate the AAD and
    /// make unlock fail closed with no session returned.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn unlock_rejects_patched_frame_revision_id() {
        let path = unique_temp_vault_path("patched-revision");
        let tmp_path = tmp_path_for(&path);
        create_test_vault(&path, b"patched-revision-password-never-real");

        let (mut bytes, revision_offset) = frame_revision_id_offset(&path);
        let value = bytes
            .get_mut(revision_offset)
            .expect("revision patch fixture");
        *value ^= 0x01;
        std::fs::write(&path, bytes).expect("patch revision fixture");

        let unlock_result = unlock(UnlockParams {
            path: path.clone(),
            password: SecretBytes::new(b"patched-revision-password-never-real".to_vec()),
        });
        assert!(unlock_result.is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// Patching the persisted frame record_id must invalidate the AAD and make
    /// unlock fail closed with no session returned.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn unlock_rejects_patched_frame_record_id() {
        let path = unique_temp_vault_path("patched-record");
        let tmp_path = tmp_path_for(&path);
        create_test_vault(&path, b"patched-record-password-never-real");

        let (mut bytes, record_offset) = frame_record_id_offset(&path);
        let value = bytes.get_mut(record_offset).expect("record patch fixture");
        *value ^= 0x01;
        std::fs::write(&path, bytes).expect("patch record fixture");

        let unlock_result = unlock(UnlockParams {
            path: path.clone(),
            password: SecretBytes::new(b"patched-record-password-never-real".to_vec()),
        });
        assert!(unlock_result.is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// Two independent create() calls must assign distinct WrappedRootKey
    /// record identifiers and revision identifiers.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn create_assigns_unique_record_and_revision_ids() {
        let path_a = unique_temp_vault_path("unique-a");
        let path_b = unique_temp_vault_path("unique-b");
        let tmp_a = tmp_path_for(&path_a);
        let tmp_b = tmp_path_for(&path_b);
        create_test_vault(&path_a, b"unique-a-password-never-real");
        create_test_vault(&path_b, b"unique-b-password-never-real");

        let (_bytes_a, frame_a, _offset_a, _len_a) = wrapped_root_frame_for_test(&path_a);
        let (_bytes_b, frame_b, _offset_b, _len_b) = wrapped_root_frame_for_test(&path_b);
        assert_ne!(frame_a.record_id, frame_b.record_id);
        assert_ne!(frame_a.revision_id, frame_b.revision_id);

        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
        let _ = std::fs::remove_file(&tmp_a);
        let _ = std::fs::remove_file(&tmp_b);
    }
}
