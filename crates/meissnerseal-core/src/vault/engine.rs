// SPDX-License-Identifier: Apache-2.0
//! Vault engine: create, unlock, and lock vault typestates.

use std::{fmt::Write as FmtWrite, io::Write, marker::PhantomData};

use meissnerseal_security::secret_lifecycle::SecretBytes;

use crate::error::{CoreError, Result};
use crate::keys::hierarchy::{create_session_keys, derive_session_keys, UnlockedKeys};
#[cfg(test)]
use crate::vault::format::RecordTableEntry;
use crate::vault::format::{
    build_aad, open_sealed_record_table_v2, parse_header, parse_record_frame, serialize_header,
    serialize_record_frame, serialize_sealed_record_table_v2, serialize_vault_file,
    HeaderKdfParams, RecordFrame, VaultHeader, FORMAT_VERSION, HEADER_MIN_LEN, KDF_ARGON2ID_V1,
    RECORD_KIND_WRAPPED_ROOT_KEY, SCHEMA_MEISSNER_RECORDS_V2,
};

// Byte offsets within the 26-byte vault file prefix (vault_format_v1.md §2).
const HEADER_LEN_OFFSET: usize = 10;
const RECORD_TABLE_LEN_OFFSET: usize = 14;

/// Locked vault state.
///
/// # Contract
///
/// ## Invariants
/// - Carries no key material.
/// - Can be obtained from [`Vault::<Locked>::create`] or [`Vault::<Locked>::open`].
pub struct Locked;

/// Unlocked vault state.
///
/// # Contract
///
/// ## Invariants
/// - Contains exactly one [`UnlockedKeys`] set.
/// - Does **not** implement `Clone`, `PartialEq`, or `Debug`.
/// - Key material is zeroized on drop via `ZeroizeOnDrop` on [`UnlockedKeys`]
///   fields.
pub struct Unlocked {
    keys: UnlockedKeys,
}

/// Vault value parameterized by lock state.
///
/// # Contract
///
/// ## Invariants
/// - `Vault<Locked>` contains only non-secret routing metadata.
/// - `Vault<Unlocked>` is the only vault type that carries live key material.
/// - Item/export operations accept `&Vault<Unlocked>` only; attempts to call
///   them on `Vault<Locked>` fail at compile time.
pub struct Vault<S> {
    path: std::path::PathBuf,
    state: S,
    _state: PhantomData<S>,
}

impl<S> Vault<S> {
    /// Borrow the path of the vault file.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Vault<Unlocked> {
    /// Borrow the unlocked vault's derived key hierarchy (crate-internal item ops only).
    pub(crate) fn keys(&self) -> &UnlockedKeys {
        &self.state.keys
    }
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

impl Vault<Locked> {
    /// Create a new locked vault at the given path.
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
    ///   for the fixed-position WrappedRootKey frame before AAD construction; those
    ///   same IDs are persisted in the §6 frame metadata.
    /// - On success: header `schema_profile` is `SCHEMA_MEISSNER_RECORDS_V2`, the WRK
    ///   frame starts at `HEADER_MIN_LEN + header_len`, and the MEK-sealed table
    ///   contains no WrappedRootKey entry.
    /// - On success: returns a [`Vault<Locked>`], never a live [`Vault<Unlocked>`].
    /// - On failure: `Err` is returned and no partial file remains on disk.
    ///
    /// ## Invariants
    /// - Write strategy: serialize → encrypt → temp file → fsync → rename → fsync
    ///   parent (CONTRACT G-01).
    /// - The MEK-sealed table is sealed with `meissnerseal-crypto` AEAD under the
    ///   `metadata_key` produced by the key hierarchy; meissnerseal-core never implements
    ///   cryptography directly.
    /// - Never writes plaintext key material to disk.
    /// - Never returns partial output on cryptographic failure (CONTRACT G-06).
    /// - A live [`Vault<Unlocked>`] is obtainable only through [`Vault<Locked>::unlock`]
    ///   (CONTRACT P-01), preserving the single session-birth chokepoint for future
    ///   sync/transfer/device/recovery and hardware re-auth layers.
    pub fn create(params: CreateVaultParams) -> Result<Self> {
        // Validate preconditions.
        params.password.with_secret(|b| -> Result<()> {
            if b.is_empty() {
                return Err(CoreError::InvalidState("empty password".into()));
            }
            Ok(())
        })?;

        // Generate vault_id and header_nonce from OS CSPRNG.
        let vault_id: [u8; 16] = meissnerseal_crypto::rng::random_bytes(16)
            .try_into()
            .map_err(|_| CoreError::Crypto)?;
        let record_id: [u8; 16] = meissnerseal_crypto::rng::random_bytes(16)
            .try_into()
            .map_err(|_| CoreError::Crypto)?;
        let revision_id: [u8; 16] = meissnerseal_crypto::rng::random_bytes(16)
            .try_into()
            .map_err(|_| CoreError::Crypto)?;
        let header_nonce = meissnerseal_crypto::rng::random_nonce_xchacha20();

        let aad = build_aad(
            &vault_id,
            FORMAT_VERSION,
            SCHEMA_MEISSNER_RECORDS_V2,
            1,
            1,
            0,
            &record_id,
            &revision_id,
            RECORD_KIND_WRAPPED_ROOT_KEY,
        );

        // Derive key hierarchy and wrap the VaultRootKey.
        let kdf_params = HeaderKdfParams::canonical_argon2id_v1();
        let (keys, wrk_ciphertext, wrk_nonce) = params.password.with_secret(|pw| {
            create_session_keys(pw, &vault_id, &header_nonce, &kdf_params, &aad)
        })?;

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
            &keys.metadata_key,
        )?;

        drop(keys);

        Ok(Self {
            path: params.path,
            state: Locked,
            _state: PhantomData,
        })
    }

    /// Open an existing vault path as locked metadata only.
    ///
    /// # Contract
    ///
    /// ## Preconditions
    /// - `path` identifies the vault file the caller intends to unlock.
    ///
    /// ## Postconditions
    /// - Returns a [`Vault<Locked>`] carrying no key material.
    ///
    /// ## Invariants
    /// - Does not parse, decrypt, derive keys, or touch plaintext.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        Ok(Self {
            path: path.into(),
            state: Locked,
            _state: PhantomData,
        })
    }

    /// Unlock an existing vault file and return a vault with decrypted key material.
    ///
    /// # Contract
    ///
    /// ## Preconditions
    /// - `params.path` must exist and be a valid vault file: correct magic bytes,
    ///   supported format version, authenticated header, and a parseable
    ///   `WrappedRootKey` record.
    /// - `params.path` must equal this locked vault's path.
    /// - `params.password` must be non-empty.
    ///
    /// ## Postconditions
    /// - On success: returns a [`Vault<Unlocked>`] with all subkeys derived and ready.
    /// - On authentication failure: returns `Err` — no key material is exposed or
    ///   partially returned.
    ///
    /// ## Invariants
    /// - Never returns a partial `Vault<Unlocked>` on decryption or AEAD failure
    ///   (CONTRACT G-06).
    /// - Rejects: wrong magic bytes, unknown critical TLV tags, truncated data,
    ///   and any AEAD authentication failure.
    pub fn unlock(self, params: UnlockParams) -> Result<Vault<Unlocked>> {
        if params.path != self.path {
            return Err(CoreError::InvalidState(
                "unlock path does not match locked vault".into(),
            ));
        }
        unlock_impl(params)
    }
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
/// - On success, `path` exists as a durable `.msv` vault file and no
///   temporary file created by this call remains.
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
/// - The temporary file path is per-call unique, derived from the
///   already-available CSPRNG-backed `record_id` rather than from the final path
///   alone. This prevents a failed concurrent writer from deleting another
///   writer's in-flight temp file.
/// - Uses the supplied `wrk_ciphertext` and `wrk_nonce`; it never re-encrypts
///   and never writes plaintext key material.
/// - Persists the supplied WrappedRootKey at fixed offset
///   `HEADER_MIN_LEN + header_len`; the sealed table must not include a
///   WrappedRootKey entry.
/// - The record table is MEK-sealed and uses a fresh table nonce for every
///   create-time seal.
///
/// ## Invariants
/// - Crash-safe order is exactly:
///   serialize header + fixed WRK frame + MEK-sealed table + item frames → write
///   unique sibling temp → fsync temp → atomic rename to `.msv` → fsync parent
///   directory.
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
    aad: &[u8; 79],
    metadata_key: &meissnerseal_crypto::types::AeadKey,
) -> Result<()> {
    let tmp_path = unique_tmp_path(path, record_id);
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
            metadata_key,
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

/// Rewrite an existing V2 vault through the mutation crash-safe path.
///
/// # Contract
///
/// ## Preconditions
/// - `path` already names the vault being rewritten; unlike [`create`], mutation
///   must not use a final-path create-new claim.
/// - `vault_bytes` is a complete V2 serialization containing the fixed-position
///   WrappedRootKey frame, a freshly re-sealed MEK table, and all encrypted item
///   frames.
/// - `unique_seed` is CSPRNG-backed per call and is used only to derive this
///   call's unique sibling temp path.
///
/// ## Postconditions
/// - On success, atomically replaces `path` with `vault_bytes`, fsyncs the temp
///   and parent directory, and leaves no temp created by this call.
/// - On failure, returns `Err`; it removes only this call's unique temp and never
///   removes a foreign temp or the existing final vault file.
/// - The record table is re-sealed under MEK on every mutation; item plaintext is
///   not touched merely to update table metadata.
///
/// ## Invariants
/// - Crash-safe order is: serialize → unique sibling temp → fsync temp → atomic
///   rename over existing vault → fsync parent.
/// - No plaintext key material or item plaintext is written to disk, logs, or
///   error values.
/// - Fail-closed: no mutation error path returns partial success.
pub(crate) fn persist_vault_mutation_v2(
    path: &std::path::Path,
    vault_bytes: &[u8],
    unique_seed: &[u8; 16],
) -> Result<()> {
    let tmp_path = unique_tmp_path(path, unique_seed);
    let result = (|| -> Result<()> {
        let mut tmp_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        tmp_file.write_all(vault_bytes)?;
        tmp_file.sync_all()?;
        drop(tmp_file);
        std::fs::rename(&tmp_path, path)?;
        fsync_parent(path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }

    result
}

fn unique_tmp_path(path: &std::path::Path, record_id: &[u8; 16]) -> std::path::PathBuf {
    path.with_extension(format!("{}.msv.tmp", hex16(record_id)))
}

fn hex16(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
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
    aad: &[u8; 79],
    metadata_key: &meissnerseal_crypto::types::AeadKey,
) -> Result<()> {
    let created_at = unix_time_millis()?;
    let header = VaultHeader {
        vault_id: *vault_id,
        created_at,
        format_version: FORMAT_VERSION,
        schema_profile: SCHEMA_MEISSNER_RECORDS_V2,
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
    let record_table_bytes =
        serialize_sealed_record_table_v2(&[], metadata_key, vault_id, SCHEMA_MEISSNER_RECORDS_V2)?;
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

pub(crate) fn record_frame_len_at(bytes: &[u8], offset: usize) -> Result<u32> {
    const FRAME_FIXED_PREFIX: usize = 2 + 16 + 16 + 2 + 1;
    let fixed_end = offset
        .checked_add(FRAME_FIXED_PREFIX)
        .ok_or_else(|| CoreError::Format("record frame prefix overflow".into()))?;
    if fixed_end > bytes.len() {
        return Err(CoreError::Format("truncated record frame".into()));
    }

    let nonce_len = usize::from(
        *bytes
            .get(
                offset
                    .checked_add(2 + 16 + 16 + 2)
                    .ok_or_else(|| CoreError::Format("nonce length offset overflow".into()))?,
            )
            .ok_or_else(|| CoreError::Format("truncated record frame".into()))?,
    );
    let aad_len_offset = fixed_end
        .checked_add(nonce_len)
        .ok_or_else(|| CoreError::Format("AAD length offset overflow".into()))?;
    let aad_len = read_u32_at(bytes, aad_len_offset)?;
    let ciphertext_len_offset = aad_len_offset
        .checked_add(4)
        .and_then(|value| value.checked_add(usize::try_from(aad_len).ok()?))
        .ok_or_else(|| CoreError::Format("ciphertext length offset overflow".into()))?;
    let ciphertext_len = read_u32_at(bytes, ciphertext_len_offset)?;
    let frame_len = ciphertext_len_offset
        .checked_add(4)
        .and_then(|value| value.checked_add(usize::try_from(ciphertext_len).ok()?))
        .and_then(|end| end.checked_sub(offset))
        .ok_or_else(|| CoreError::Format("record frame length overflow".into()))?;
    u32::try_from(frame_len).map_err(|_| CoreError::Format("record frame length overflow".into()))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| CoreError::Format("u32 read overflow".into()))?;
    let array: [u8; 4] = bytes
        .get(offset..end)
        .ok_or_else(|| CoreError::Format("truncated u32 field".into()))?
        .try_into()
        .map_err(|_| CoreError::Format("u32 read error".into()))?;
    Ok(u32::from_le_bytes(array))
}

/// Unlock implementation shared by the typestate transition.
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
/// - On success: returns a [`Vault<Unlocked>`] with all subkeys derived and ready.
/// - On authentication failure: returns `Err` — no key material is exposed or
///   partially returned.
///
/// ## Invariants
/// - Never returns a partial `Vault<Unlocked>` on decryption or AEAD failure
///   (CONTRACT G-06).
/// - Rejects: wrong magic bytes, unknown critical TLV tags, truncated data,
///   and any AEAD authentication failure.
fn unlock_impl(params: UnlockParams) -> Result<Vault<Unlocked>> {
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

    let wrk_frame_offset = HEADER_MIN_LEN
        .checked_add(header_len)
        .ok_or_else(|| CoreError::Format("WRK frame offset overflow".into()))?;
    let wrk_frame_len = record_frame_len_at(&bytes, wrk_frame_offset)?;

    // Parse the encrypted frame.
    let frame_slice = bytes
        .get(wrk_frame_offset..)
        .ok_or_else(|| CoreError::Format("frame offset out of bounds".into()))?;
    let frame = parse_record_frame(frame_slice, wrk_frame_len)?;

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

    let wrk_frame_len_usize = usize::try_from(wrk_frame_len)
        .map_err(|_| CoreError::Format("WRK frame length overflow".into()))?;
    let record_table_offset = wrk_frame_offset
        .checked_add(wrk_frame_len_usize)
        .ok_or_else(|| CoreError::Format("record table offset overflow".into()))?;
    open_sealed_record_table_v2(
        &bytes,
        record_table_offset,
        record_table_len,
        &keys.metadata_key,
        &header.vault_id,
        header.schema_profile,
        wrk_frame_offset,
        bytes.len(),
    )?;

    Ok(Vault {
        path: params.path,
        state: Unlocked { keys },
        _state: PhantomData,
    })
}

impl Vault<Unlocked> {
    /// Lock a vault, consuming it and zeroizing all key material.
    ///
    /// # Contract
    ///
    /// ## Preconditions
    /// - `self` was obtained through [`Vault<Locked>::unlock`].
    ///
    /// ## Postconditions
    /// - The [`UnlockedKeys`] held in `self` is dropped; all 32-byte key fields
    ///   are zeroized via `ZeroizeOnDrop` on `meissnerseal_crypto::types::Key<32>`.
    /// - Returns a [`Vault<Locked>`] containing the same path and no key material.
    ///
    /// ## Invariants
    /// - Consuming ownership via `self` ensures the caller cannot reference the
    ///   unlocked vault after this call — enforced by the Rust type system,
    ///   not by a runtime check.
    pub fn lock(self) -> Vault<Locked> {
        let path = self.path;
        drop(self.state);
        Vault {
            path,
            state: Locked,
            _state: PhantomData,
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn locked_vault_has_no_key_material_storage() {
        let vault = Vault::<Locked> {
            path: std::path::PathBuf::new(),
            state: Locked,
            _state: PhantomData,
        };

        assert_eq!(
            std::mem::size_of_val(&vault),
            std::mem::size_of::<std::path::PathBuf>()
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::vault::format::SCHEMA_MEISSNER_RECORDS_V2;
    use meissnerseal_crypto::types::AeadKey;
    use meissnerseal_security::secret_lifecycle::SecretBytes;
    use static_assertions::assert_not_impl_any;

    fn unique_temp_vault_path(label: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir(); // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        path.push(format!(
            "meissnerseal-core-{label}-{}-{nanos}.msv",
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
        let frame_offset = HEADER_MIN_LEN
            .checked_add(header_len)
            .expect("fixed WRK frame offset fixture");
        let frame_len =
            record_frame_len_at(&bytes, frame_offset).expect("WRK frame length fixture");
        let frame_bytes = bytes.get(frame_offset..).expect("frame fixture slice");
        let frame = parse_record_frame(frame_bytes, frame_len).expect("frame");
        (bytes, frame, frame_offset, frame_len)
    }

    fn parsed_header_for_test(path: &std::path::Path) -> VaultHeader {
        let bytes = std::fs::read(path).expect("read vault fixture");
        parse_header(&bytes).expect("parse header fixture")
    }

    fn record_table_entries_for_test(
        path: &std::path::Path,
        password: &[u8],
    ) -> Vec<RecordTableEntry> {
        let bytes = std::fs::read(path).expect("read vault fixture");
        let header = parse_header(&bytes).expect("parse header fixture");
        let header_len = usize::try_from(read_u32_for_test(&bytes, HEADER_LEN_OFFSET))
            .expect("header length fixture");
        let record_table_len = usize::try_from(read_u32_for_test(&bytes, RECORD_TABLE_LEN_OFFSET))
            .expect("record table length fixture");
        let wrk_frame_offset = HEADER_MIN_LEN
            .checked_add(header_len)
            .expect("fixed WRK frame offset fixture");
        let wrk_frame_len =
            record_frame_len_at(&bytes, wrk_frame_offset).expect("WRK frame length fixture");
        let record_table_offset = wrk_frame_offset
            .checked_add(usize::try_from(wrk_frame_len).expect("WRK frame length usize"))
            .expect("record table offset fixture");
        let session = unlock(UnlockParams {
            path: path.to_path_buf(),
            password: SecretBytes::new(password.to_vec()),
        })
        .expect("unlock fixture");
        let entries = open_sealed_record_table_v2(
            &bytes,
            record_table_offset,
            record_table_len,
            &session.keys().metadata_key,
            &header.vault_id,
            header.schema_profile,
            wrk_frame_offset,
            bytes.len(),
        )
        .expect("sealed record table");
        lock(session).expect("lock fixture");
        entries
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
        let locked = create(CreateVaultParams {
            path: path.to_path_buf(),
            password: SecretBytes::new(password.to_vec()),
        })
        .expect("create fixture");
        assert_eq!(locked.path(), path);
    }

    fn create(params: CreateVaultParams) -> Result<Vault<Locked>> {
        Vault::<Locked>::create(params)
    }

    fn unlock(params: UnlockParams) -> Result<Vault<Unlocked>> {
        Vault::<Locked>::open(params.path.clone())?.unlock(params)
    }

    fn lock(vault: Vault<Unlocked>) -> Result<()> {
        let _locked = vault.lock();
        Ok(())
    }

    // Compile-time gate: Vault<Unlocked> must never implement Debug.
    // If Debug is derived, key material can appear in log output.
    // Adding #[derive(Debug)] to Vault<Unlocked> breaks this assertion at compile time.
    assert_not_impl_any!(Vault<Unlocked>: std::fmt::Debug);
    assert_not_impl_any!(Vault<Locked>: UnlockedVaultOps);

    trait UnlockedVaultOps {}
    impl UnlockedVaultOps for Vault<Unlocked> {}

    /// `create()` rejects an empty password without producing any key material.
    #[test]
    fn test_create_rejects_empty_password() {
        let params = CreateVaultParams {
            path: std::path::PathBuf::from("/tmp/should-not-exist-meissnerseal-test.msv"),
            password: SecretBytes::new(vec![]),
        };
        assert!(create(params).is_err());
    }

    /// `unlock()` rejects an empty password without reading the file.
    #[test]
    fn test_unlock_rejects_empty_password() {
        let params = UnlockParams {
            path: std::path::PathBuf::from("/tmp/does-not-exist-meissnerseal.msv"),
            password: SecretBytes::new(vec![]),
        };
        assert!(unlock(params).is_err());
    }

    /// `create()` succeeds with a valid password and returns only a locked vault;
    /// the unlocked vault is obtained through `unlock()` and then locked again.
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
        let locked = create(params).expect("create must return locked vault");
        assert_eq!(locked.path(), path);
        let session = unlock(UnlockParams {
            path: locked.path().to_path_buf(),
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
            assert_eq!(handle.path(), path);
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
        let mut path = std::env::temp_dir(); // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        path.push(format!(
            "meissnerseal-core-missing-parent-{}-{nanos}",
            std::process::id()
        ));
        path.push("failure-cleanup.msv");
        let tmp_path = tmp_path_for(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
        let metadata_key = AeadKey::from_bytes([0x99; 32]);

        let result = persist_vault(
            &path,
            &[0x11; 16],
            &[0x22; 24],
            &HeaderKdfParams::canonical_argon2id_v1(),
            &[0x66; 16],
            &[0x77; 16],
            &[0x33; 32],
            &[0x44; 24],
            &[0x55; 79],
            &metadata_key,
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
        let metadata_key = AeadKey::from_bytes([0x99; 32]);

        let result = persist_vault(
            &path,
            &[0x11; 16],
            &[0x22; 24],
            &HeaderKdfParams::canonical_argon2id_v1(),
            &[0x66; 16],
            &[0x77; 16],
            &[0x33; 32],
            &[0x44; 24],
            &[0x55; 79],
            &metadata_key,
        );

        assert!(result.is_err());
        assert!(!tmp_path.exists());
        let preserved = std::fs::read(&path).expect("pre-existing target must remain");
        assert_eq!(preserved, original);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// A failed concurrent writer must not delete another writer's in-flight
    /// temp file. This deterministically models the race:
    ///
    /// 1. winner has already claimed `path` and written valid vault bytes to its
    ///    temp file;
    /// 2. loser calls the real `persist_vault`, fails the target claim, and runs
    ///    its error cleanup;
    /// 3. winner must still be able to rename its temp into place and unlock.
    ///
    /// Phase 1 is intentionally red because the current cleanup removes the
    /// deterministic `path.with_extension("arcv.tmp")` at `persist_vault`.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn concurrent_loser_does_not_delete_winner_temp() {
        let path = unique_temp_vault_path("concurrent-temp-owner");
        let tmp_path = tmp_path_for(&path);
        let source_path = unique_temp_vault_path("concurrent-temp-source");
        let source_tmp_path = tmp_path_for(&source_path);
        let password = b"concurrent-temp-password-never-real";
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
        let _ = std::fs::remove_file(&source_path);
        let _ = std::fs::remove_file(&source_tmp_path);

        create_test_vault(&source_path, password);
        let source_bytes = std::fs::read(&source_path).expect("read source vault fixture");
        std::fs::write(&tmp_path, source_bytes).expect("write winner temp fixture");
        let target_claim = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("winner target claim fixture");
        let metadata_key = AeadKey::from_bytes([0x99; 32]);

        let loser_result = persist_vault(
            &path,
            &[0x11; 16],
            &[0x22; 24],
            &HeaderKdfParams::canonical_argon2id_v1(),
            &[0x66; 16],
            &[0x77; 16],
            &[0x33; 32],
            &[0x44; 24],
            &[0x55; 79],
            &metadata_key,
        );
        assert!(loser_result.is_err());
        assert!(
            tmp_path.exists(),
            "loser cleanup must not delete winner-owned temp"
        );

        drop(target_claim);
        std::fs::rename(&tmp_path, &path).expect("winner rename must still succeed");
        assert!(path.exists());
        assert!(!tmp_path.exists());

        let unlock_result = unlock(UnlockParams {
            path: path.clone(),
            password: SecretBytes::new(password.to_vec()),
        });
        assert!(unlock_result.is_ok());
        if let Ok(session) = unlock_result {
            assert!(lock(session).is_ok());
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
        let _ = std::fs::remove_file(&source_path);
        let _ = std::fs::remove_file(&source_tmp_path);
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

    /// A successful create leaves a durable `.msv` file at the requested path
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
        if let Ok(locked) = result {
            assert_eq!(locked.path(), path);
        }
        assert!(path.exists());
        assert!(!tmp_path.exists());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// `create()` returns a non-secret locked vault, not an unlocked vault;
    /// opening the created vault requires an explicit `unlock()` call.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn create_returns_locked_vault_not_unlocked_vault() {
        let path = unique_temp_vault_path("locked-only");
        let tmp_path = tmp_path_for(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);

        let locked = create(CreateVaultParams {
            path: path.clone(),
            password: SecretBytes::new(b"locked-only-password-never-real".to_vec()),
        })
        .expect("create must return locked vault");
        assert_eq!(locked.path(), path);
        assert!(locked.path().exists());

        let session = unlock(UnlockParams {
            path: locked.path().to_path_buf(),
            password: SecretBytes::new(b"locked-only-password-never-real".to_vec()),
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

    /// V2 keeps WrappedRootKey metadata out of the sealed table because the WRK
    /// frame is fixed-position and authenticated by its §6 frame metadata.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn create_persists_wrk_frame_ids_without_wrk_table_entry() {
        let path = unique_temp_vault_path("table-frame-revision");
        let tmp_path = tmp_path_for(&path);
        let password = b"table-frame-revision-password-never-real";
        create_test_vault(&path, password);

        let (_bytes, frame, _frame_offset, _frame_len) = wrapped_root_frame_for_test(&path);
        assert_ne!(frame.record_id, [0u8; 16]);
        assert_ne!(frame.revision_id, [0u8; 16]);
        let entries = record_table_entries_for_test(&path, password);
        assert!(
            entries
                .iter()
                .all(|entry| entry.record_kind != RECORD_KIND_WRAPPED_ROOT_KEY),
            "V2 sealed table must not contain a WrappedRootKey entry"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// V2 create writes schema_profile = 0x0002; V1 is pre-release and must not
    /// be emitted by MVP-0 writers.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn create_writes_schema_profile_v2_header() {
        let path = unique_temp_vault_path("schema-v2");
        let tmp_path = tmp_path_for(&path);
        create_test_vault(&path, b"schema-v2-password-never-real");

        let header = parsed_header_for_test(&path);
        assert_eq!(header.schema_profile, SCHEMA_MEISSNER_RECORDS_V2);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// V2 locates the WrappedRootKey frame by fixed offset: 26 + header_len. It
    /// must not be located through a cleartext table entry.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn create_places_wrk_frame_at_fixed_position_after_header() {
        let path = unique_temp_vault_path("fixed-wrk");
        let tmp_path = tmp_path_for(&path);
        create_test_vault(&path, b"fixed-wrk-password-never-real");

        let bytes = std::fs::read(&path).expect("read vault fixture");
        let header_len = usize::try_from(read_u32_for_test(&bytes, HEADER_LEN_OFFSET))
            .expect("header length fixture");
        let (_bytes, _frame, frame_offset, _frame_len) = wrapped_root_frame_for_test(&path);
        let fixed_offset = HEADER_MIN_LEN
            .checked_add(header_len)
            .expect("fixed WRK offset fixture");
        assert_eq!(frame_offset, fixed_offset);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// V2 sealed tables must not contain `record_kind = 0x0002`; WRK metadata is
    /// not a table entry because the WRK frame is fixed-position.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn create_v2_table_contains_no_wrapped_root_key_entry() {
        let path = unique_temp_vault_path("no-wrk-entry");
        let tmp_path = tmp_path_for(&path);
        let password = b"no-wrk-entry-password-never-real";
        create_test_vault(&path, password);

        let entries = record_table_entries_for_test(&path, password);
        assert!(
            entries
                .iter()
                .all(|entry| entry.record_kind != RECORD_KIND_WRAPPED_ROOT_KEY),
            "V2 sealed table must not contain a WrappedRootKey entry"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// Existing-vault mutation rewrites through the V2 crash-safe path and must
    /// not use create-new final-path claiming. It re-seals the table and leaves
    /// no sibling temp.
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn mutation_rewrite_uses_v2_crash_safe_path_and_leaves_no_tmp() {
        let path = unique_temp_vault_path("mutation-v2");
        let tmp_path = tmp_path_for(&path);
        create_test_vault(&path, b"mutation-v2-password-never-real");
        let bytes = std::fs::read(&path).expect("read vault fixture");

        let result = persist_vault_mutation_v2(&path, &bytes, &[0x91; 16]);

        assert!(result.is_ok());
        assert!(path.exists());
        assert!(!tmp_path.exists());

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
