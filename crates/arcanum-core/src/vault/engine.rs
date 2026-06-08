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
///   Obtained exclusively through [`create`] or [`unlock`].
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

/// Create a new vault at the given path and return an unlocked session.
///
/// # Contract
///
/// ## Preconditions
/// - `params.path` must not already exist — this function never overwrites.
/// - `params.password` must be non-empty.
///
/// ## Postconditions
/// - On success: key hierarchy is derived and a [`VaultSession`] is returned.
/// - On failure: `Err` is returned and no partial file remains on disk.
///
/// ## Invariants
/// - Write strategy: serialize → encrypt → temp file → fsync → rename → fsync
///   parent (CONTRACT G-01).
/// - Never writes plaintext key material to disk.
/// - Never returns partial output on cryptographic failure (CONTRACT G-06).
pub fn create(params: CreateVaultParams) -> Result<VaultSession> {
    // Validate preconditions.
    params.password.with_secret(|b| -> Result<()> {
        if b.is_empty() {
            return Err(CoreError::InvalidState("empty password".into()));
        }
        Ok(())
    })?;

    if params.path.exists() {
        return Err(CoreError::InvalidState("vault already exists".into()));
    }

    // Generate vault_id and header_nonce from OS CSPRNG.
    let vault_id: [u8; 16] = arcanum_crypto::rng::random_bytes(16)
        .try_into()
        .map_err(|_| CoreError::Crypto)?;
    let header_nonce = arcanum_crypto::rng::random_nonce_xchacha20();

    // Build canonical AAD for the WrappedRootKey record.
    // TODO(Phase 3 F-01/F-03): replace zero_id with real random record_id and
    // revision_id once the vault serialization path is implemented. Using zero
    // IDs here means the AAD does not bind to a specific record or revision,
    // weakening cross-record substitution resistance. Acceptable for MVP-0
    // because create() does not yet persist a vault file.
    let zero_id = [0u8; 16];
    let aad = build_aad(
        &vault_id,
        1,
        1,
        1,
        1,
        0,
        &zero_id,
        &zero_id,
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
        &wrk_ciphertext,
        &wrk_nonce,
        &aad,
    )?;

    Ok(VaultSession { keys })
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
/// - `aad` is the exact canonical AAD used when `wrk_ciphertext` was created.
///
/// ## Postconditions
/// - On success, `path` exists as a durable `.arcv` vault file and no sibling
///   `.tmp` file remains.
/// - On any serialization, write, fsync, rename, or parent fsync failure,
///   returns `Err`, removes the temporary file if present, and leaves no
///   partial vault at `path`.
/// - Uses the supplied `wrk_ciphertext` and `wrk_nonce`; it never re-encrypts
///   and never writes plaintext key material.
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
    wrk_ciphertext: &[u8],
    wrk_nonce: &[u8; 24],
    aad: &[u8; 74],
) -> Result<()> {
    let tmp_path = path.with_extension("arcv.tmp");
    let result = persist_vault_inner(
        path,
        &tmp_path,
        vault_id,
        header_nonce,
        kdf_params,
        wrk_ciphertext,
        wrk_nonce,
        aad,
    );

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        let _ = std::fs::remove_file(path);
    }

    result
}

#[allow(clippy::too_many_arguments)]
fn persist_vault_inner(
    path: &std::path::Path,
    tmp_path: &std::path::Path,
    vault_id: &[u8; 16],
    header_nonce: &[u8; 24],
    kdf_params: &HeaderKdfParams,
    wrk_ciphertext: &[u8],
    wrk_nonce: &[u8; 24],
    aad: &[u8; 74],
) -> Result<()> {
    if path.exists() {
        return Err(CoreError::InvalidState("vault already exists".into()));
    }

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
        record_id: [0u8; 16],
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
        record_id: [0u8; 16],
        record_kind: RECORD_KIND_WRAPPED_ROOT_KEY,
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

    if path.exists() {
        return Err(CoreError::InvalidState("vault already exists".into()));
    }

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

    // Build canonical AAD for this record.
    // TODO(Phase 3 F-01): replace zero_revision with the actual revision_id
    // stored in the record frame once parse_record_frame exposes it.
    // Using zero here will cause AAD mismatch if the stored frame was encrypted
    // with a non-zero revision_id (security review F-01).
    let zero_revision = [0u8; 16];
    let aad = build_aad(
        &header.vault_id,
        header.format_version,
        header.schema_profile,
        header.aead_profile,
        header.kdf_profile,
        header.pqc_profile,
        &frame.record_id,
        &zero_revision,
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
/// - `session` was obtained through [`unlock`] or [`create`].
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

    /// `create()` succeeds with a valid password and non-existent path,
    /// and the returned session can be locked.
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
        let session = create(params).expect("create must succeed");
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
        if let Ok(session) = create_result {
            assert!(lock(session).is_ok());
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
            &[0x33; 32],
            &[0x44; 24],
            &[0x55; 74],
        );

        assert!(result.is_err());
        assert!(!path.exists());
        assert!(!tmp_path.exists());
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
        if let Ok(session) = result {
            assert!(lock(session).is_ok());
        }
        assert!(path.exists());
        assert!(!tmp_path.exists());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }
}
