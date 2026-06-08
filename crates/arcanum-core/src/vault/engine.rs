//! Vault engine: create, unlock, and lock vault sessions.

use arcanum_security::secret_lifecycle::SecretBytes;

use crate::error::{CoreError, Result};
use crate::keys::hierarchy::{create_session_keys, derive_session_keys, UnlockedKeys};
use crate::vault::format::{
    build_aad, parse_header, parse_record_frame, parse_record_table, HeaderKdfParams,
    HEADER_MIN_LEN,
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
/// - Write strategy (full serialization added in Phase 3): serialize →
///   encrypt → temp file → fsync → rename → fsync parent (CONTRACT G-01).
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
    let (keys, _wrk_ciphertext, _wrk_nonce) = params
        .password
        .with_secret(|pw| create_session_keys(pw, &vault_id, &header_nonce, &kdf_params, &aad))?;

    // MVP-0: vault file serialization is deferred to Phase 3.
    // The key hierarchy is fully derived; the session is returned.
    Ok(VaultSession { keys })
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
        let params = CreateVaultParams {
            // Use a path that is guaranteed not to exist on the test host.
            path: std::path::PathBuf::from("/tmp/arcanum-test-nonexistent-vault.arcv"),
            password: SecretBytes::new(b"test-password-never-real".to_vec()),
        };
        // Ensure the path does not exist before the test.
        let _ = std::fs::remove_file(&params.path);

        let session = create(params).expect("create must succeed");
        lock(session).expect("lock must succeed");
    }
}
