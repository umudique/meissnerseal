// SPDX-License-Identifier: Apache-2.0
//! Encrypted `.msexp` export/import surface.

use meissnerseal_crypto::{
    aead::{decrypt, encrypt, Ciphertext},
    kdf::argon2::derive,
    types::{AeadKey, XChaCha20Nonce},
};
use meissnerseal_security::secret_lifecycle::SecretBytes;
use zeroize::Zeroize;

use crate::{
    error::{CoreError, Result},
    item::{
        add, delete, list,
        model::{ItemId, ItemKind, PlainItem},
        with_item,
    },
    vault::engine::VaultSession,
    vault::format::{
        parse_header, parse_kdf_profile_params, serialize_kdf_profile_params, HeaderKdfParams,
    },
};

/// Magic bytes for the encrypted Arcanum export container.
///
/// The value is public format metadata, not secret material.
pub const ARCEXP_MAGIC: [u8; 8] = *b"ARCEXP\x01\0";

/// MVP-0 encrypted export container version.
pub const ARCEXP_VERSION_V1: u16 = 1;

const MAGIC_LEN: usize = 8;
const VERSION_LEN: usize = 2;
const VAULT_ID_LEN: usize = 16;
const KDF_PARAMS_LEN_FIELD: usize = 4;
const NONCE_LEN: usize = 24;
const CIPHERTEXT_LEN_FIELD: usize = 4;
const MIN_BUNDLE_LEN: usize = MAGIC_LEN
    + VERSION_LEN
    + VAULT_ID_LEN
    + KDF_PARAMS_LEN_FIELD
    + NONCE_LEN
    + CIPHERTEXT_LEN_FIELD;

/// Export the live item set from an unlocked vault into an encrypted `.msexp`
/// bundle protected by a user-supplied export passphrase.
///
/// # Contract
///
/// ## Preconditions
/// - `session` was obtained through `vault::unlock`; callers cannot construct a
///   live [`VaultSession`] directly.
/// - `passphrase` must be non-empty secret material supplied by the user for
///   this export bundle. It is independent from the vault master password and
///   from vault-internal HKDF subkeys.
/// - The vault's sealed record table opens successfully under the Metadata
///   Encryption Key, and every live item record authenticates before inclusion.
///
/// ## Postconditions
/// - On success, returns a versioned `.msexp` byte container:
///   `ARCEXP_MAGIC[8] || version:u16le || source_vault_id[16] ||
///   kdf_params_len:u32le || kdf_params[N] || nonce[24] ||
///   ciphertext_len:u32le || ciphertext_and_tag`.
/// - `kdf_params` is the Argon2id parameter TLV structure used to derive the
///   export AEAD key from `passphrase` via `KDF_ARGON2ID_V1`; it includes the
///   export salt needed for cross-vault import.
/// - Export AEAD AAD is exactly
///   `source_vault_id[16] || ARCEXP_MAGIC[8] || version:u16le`.
/// - The plaintext serialized inside the encrypted payload is exactly the
///   vault's live item set at export time: tombstones and non-item records are
///   excluded.
/// - Returns `Err` with no partial bundle if table authentication, item
///   authentication, KDF, serialization, RNG, or AEAD sealing fails.
///
/// ## Invariants
/// - meissnerseal-core provides no plaintext export path; unsafe plaintext import or
///   export flags belong only in meissnerseal-cli.
/// - Uses only `meissnerseal-crypto` for Argon2id, RNG, and AEAD operations; this
///   crate never implements cryptography directly.
/// - Export never writes plaintext item bytes, labels, tags, export
///   passphrase, derived export key bytes, or vault key material to disk, logs,
///   audit events, or error values.
pub fn export(session: &VaultSession, passphrase: &[u8]) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(CoreError::InvalidState("empty export passphrase".into()));
    }

    let source_vault_id = session_vault_id(session)?;
    let kdf_params = HeaderKdfParams::canonical_argon2id_v1();
    let kdf_params_bytes = serialize_kdf_profile_params(&kdf_params)?;
    let mut plaintext = serialize_live_item_set(session)?;
    let export_key = derive_export_key(passphrase, &source_vault_id, &kdf_params)?;
    let aad = export_aad(&source_vault_id, ARCEXP_VERSION_V1);
    let encrypt_result = encrypt(&export_key, &plaintext, &aad);
    plaintext.zeroize();
    drop(export_key);

    let (ciphertext, nonce) = encrypt_result.map_err(|_| CoreError::Crypto)?;
    serialize_bundle(
        &source_vault_id,
        &kdf_params_bytes,
        nonce.as_slice(),
        ciphertext.as_ref(),
    )
}

/// Import an encrypted `.msexp` bundle into an unlocked vault using the
/// user-supplied export passphrase.
///
/// # Contract
///
/// ## Preconditions
/// - `session` was obtained through `vault::unlock`.
/// - `bundle` is an untrusted byte slice received from disk, transfer, or a
///   caller boundary.
/// - `passphrase` must be the user-supplied export passphrase for this bundle.
///
/// ## Postconditions
/// - Parses only the MVP-0 encrypted export container:
///   `ARCEXP_MAGIC[8] || version:u16le || source_vault_id[16] ||
///   kdf_params_len:u32le || kdf_params[N] || nonce[24] ||
///   ciphertext_len:u32le || ciphertext_and_tag`.
/// - Re-derives the export AEAD key from `passphrase` and the cleartext
///   Argon2id `kdf_params` carried by the bundle.
/// - Export AEAD AAD is exactly
///   `source_vault_id[16] || ARCEXP_MAGIC[8] || version:u16le`, reconstructed
///   from the parsed framing before decryption.
/// - Rejects wrong magic bytes, unknown versions, malformed or truncated
///   framing, ciphertext lengths that overrun the input, trailing garbage,
///   invalid KDF parameters, wrong passphrase, and any AEAD authentication
///   failure.
/// - On success, validates the decrypted item set, imports it through the same
///   encrypted V2 item-record path as `item::add`, and returns the imported
///   item IDs. Cross-vault import is supported when the same export passphrase
///   is supplied.
/// - On any failure, returns `Err` without writing a partial item, table,
///   record frame, plaintext, passphrase, or key material.
///
/// ## Invariants
/// - All cryptography is delegated to `meissnerseal-crypto`; meissnerseal-core does not
///   implement AEAD, KDF, or RNG logic directly.
/// - Plaintext import formats are not accepted here. The CLI-only
///   `--unsafe-plaintext` development path must not call this function with
///   plaintext JSON/CSV.
/// - Import never logs, audits, formats, or returns plaintext item contents,
///   the export passphrase, or derived key material.
pub fn import(session: &VaultSession, bundle: &[u8], passphrase: &[u8]) -> Result<Vec<ItemId>> {
    if passphrase.is_empty() {
        return Err(CoreError::InvalidState("empty export passphrase".into()));
    }

    let parsed = parse_bundle(bundle)?;
    let kdf_params = parse_kdf_profile_params(parsed.kdf_params)?;
    let export_key = derive_export_key(passphrase, &parsed.source_vault_id, &kdf_params)?;
    let aad = export_aad(&parsed.source_vault_id, parsed.version);
    let nonce = XChaCha20Nonce::from_bytes(parsed.nonce);
    let ciphertext = Ciphertext::from(parsed.ciphertext_and_tag.to_vec());
    let plaintext = decrypt(&export_key, &nonce, &ciphertext, &aad).map_err(|_| CoreError::Auth)?;
    drop(export_key);

    let items = deserialize_item_set(plaintext.as_ref())?;
    drop(plaintext);

    let mut imported_ids = Vec::with_capacity(items.len());
    for item in items {
        match add(session, item) {
            Ok(id) => imported_ids.push(id),
            Err(_) => {
                let rollback_ok = imported_ids.iter().all(|&id| delete(session, id).is_ok());
                if rollback_ok {
                    return Err(CoreError::InvalidState(
                        "import add failed; rollback succeeded".into(),
                    ));
                } else {
                    return Err(CoreError::PartialImport);
                }
            }
        }
    }
    Ok(imported_ids)
}

struct ParsedBundle<'a> {
    version: u16,
    source_vault_id: [u8; 16],
    kdf_params: &'a [u8],
    nonce: [u8; 24],
    ciphertext_and_tag: &'a [u8],
}

fn session_vault_id(session: &VaultSession) -> Result<[u8; 16]> {
    let bytes = std::fs::read(session.path())?;
    Ok(parse_header(&bytes)?.vault_id)
}

fn derive_export_key(
    passphrase: &[u8],
    source_vault_id: &[u8; 16],
    kdf_params: &HeaderKdfParams,
) -> Result<AeadKey> {
    let muk =
        derive(passphrase, source_vault_id, &kdf_params.argon2).map_err(|_| CoreError::Crypto)?;
    let mut raw: [u8; 32] = muk.as_slice().try_into().map_err(|_| CoreError::Crypto)?;
    let export_key = AeadKey::from_bytes(raw);
    raw.zeroize();
    drop(muk);
    Ok(export_key)
}

fn export_aad(source_vault_id: &[u8; 16], version: u16) -> [u8; 26] {
    let mut aad = [0u8; 26];
    aad[0..16].copy_from_slice(source_vault_id);
    aad[16..24].copy_from_slice(&ARCEXP_MAGIC);
    aad[24..26].copy_from_slice(&version.to_le_bytes());
    aad
}

fn serialize_bundle(
    source_vault_id: &[u8; 16],
    kdf_params: &[u8],
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(CoreError::Format("invalid export nonce length".into()));
    }
    let kdf_len = u32::try_from(kdf_params.len())
        .map_err(|_| CoreError::Format("export KDF params length overflow".into()))?;
    let ciphertext_len = u32::try_from(ciphertext_and_tag.len())
        .map_err(|_| CoreError::Format("export ciphertext length overflow".into()))?;
    let capacity = MIN_BUNDLE_LEN
        .checked_add(kdf_params.len())
        .and_then(|len| len.checked_add(ciphertext_and_tag.len()))
        .ok_or_else(|| CoreError::Format("export bundle length overflow".into()))?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&ARCEXP_MAGIC);
    out.extend_from_slice(&ARCEXP_VERSION_V1.to_le_bytes());
    out.extend_from_slice(source_vault_id);
    out.extend_from_slice(&kdf_len.to_le_bytes());
    out.extend_from_slice(kdf_params);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext_len.to_le_bytes());
    out.extend_from_slice(ciphertext_and_tag);
    Ok(out)
}

fn parse_bundle(bundle: &[u8]) -> Result<ParsedBundle<'_>> {
    if bundle.len() < MIN_BUNDLE_LEN {
        return Err(CoreError::Format("truncated export bundle".into()));
    }
    let magic = bundle
        .get(0..MAGIC_LEN)
        .ok_or_else(|| CoreError::Format("truncated export magic".into()))?;
    if magic != ARCEXP_MAGIC {
        return Err(CoreError::Format("wrong export magic".into()));
    }

    let version = read_u16(bundle, MAGIC_LEN, "export version")?;
    if version != ARCEXP_VERSION_V1 {
        return Err(CoreError::Format("unsupported export version".into()));
    }

    let source_vault_id_offset = MAGIC_LEN + VERSION_LEN;
    let source_vault_id: [u8; 16] = bundle
        .get(source_vault_id_offset..source_vault_id_offset + VAULT_ID_LEN)
        .ok_or_else(|| CoreError::Format("truncated export vault id".into()))?
        .try_into()
        .map_err(|_| CoreError::Format("export vault id read error".into()))?;

    let kdf_len_offset = source_vault_id_offset + VAULT_ID_LEN;
    let kdf_len = usize::try_from(read_u32(
        bundle,
        kdf_len_offset,
        "export KDF params length",
    )?)
    .map_err(|_| CoreError::Format("export KDF params length overflow".into()))?;
    let kdf_params_offset = kdf_len_offset
        .checked_add(KDF_PARAMS_LEN_FIELD)
        .ok_or_else(|| CoreError::Format("export KDF params offset overflow".into()))?;
    let kdf_params_end = kdf_params_offset
        .checked_add(kdf_len)
        .ok_or_else(|| CoreError::Format("export KDF params length overflow".into()))?;
    let kdf_params = bundle
        .get(kdf_params_offset..kdf_params_end)
        .ok_or_else(|| CoreError::Format("truncated export KDF params".into()))?;

    let nonce_end = kdf_params_end
        .checked_add(NONCE_LEN)
        .ok_or_else(|| CoreError::Format("export nonce offset overflow".into()))?;
    let nonce: [u8; 24] = bundle
        .get(kdf_params_end..nonce_end)
        .ok_or_else(|| CoreError::Format("truncated export nonce".into()))?
        .try_into()
        .map_err(|_| CoreError::Format("export nonce read error".into()))?;

    let ciphertext_len_offset = nonce_end;
    let ciphertext_len = usize::try_from(read_u32(
        bundle,
        ciphertext_len_offset,
        "export ciphertext length",
    )?)
    .map_err(|_| CoreError::Format("export ciphertext length overflow".into()))?;
    let ciphertext_offset = ciphertext_len_offset
        .checked_add(CIPHERTEXT_LEN_FIELD)
        .ok_or_else(|| CoreError::Format("export ciphertext offset overflow".into()))?;
    let ciphertext_end = ciphertext_offset
        .checked_add(ciphertext_len)
        .ok_or_else(|| CoreError::Format("export ciphertext length overflow".into()))?;
    if ciphertext_end != bundle.len() {
        return Err(CoreError::Format("export bundle trailing garbage".into()));
    }
    let ciphertext_and_tag = bundle
        .get(ciphertext_offset..ciphertext_end)
        .ok_or_else(|| CoreError::Format("truncated export ciphertext".into()))?;

    Ok(ParsedBundle {
        version,
        source_vault_id,
        kdf_params,
        nonce,
        ciphertext_and_tag,
    })
}

fn serialize_live_item_set(session: &VaultSession) -> Result<Vec<u8>> {
    let summaries = list(session)?;
    let mut out = Vec::new();
    out.extend_from_slice(
        &u32::try_from(summaries.len())
            .map_err(|_| CoreError::Format("export item count overflow".into()))?
            .to_le_bytes(),
    );

    for summary in summaries {
        with_item(session, summary.id, |view| {
            out.extend_from_slice(&view.kind.as_u16().to_le_bytes());
            write_len_bytes(
                &mut out,
                view.label.as_bytes(),
                "export label length overflow",
            )?;
            out.extend_from_slice(
                &u32::try_from(view.tags.len())
                    .map_err(|_| CoreError::Format("export tag count overflow".into()))?
                    .to_le_bytes(),
            );
            for tag in view.tags {
                write_len_bytes(&mut out, tag.as_bytes(), "export tag length overflow")?;
            }
            view.secret.with_secret(|secret| {
                write_len_bytes(&mut out, secret, "export secret length overflow")
            })
        })?;
    }
    Ok(out)
}

fn deserialize_item_set(bytes: &[u8]) -> Result<Vec<PlainItem>> {
    let mut cursor = 0usize;
    let item_count = take_u32(bytes, &mut cursor, "export item count")?;
    let mut items = Vec::with_capacity(item_count);
    for _ in 0..item_count {
        let kind = ItemKind::from_u16(take_u16(bytes, &mut cursor, "export item kind")?)?;
        let label = take_utf8(bytes, &mut cursor, "export item label")?;
        let tag_count = take_u32(bytes, &mut cursor, "export tag count")?;
        let mut tags = Vec::with_capacity(tag_count);
        for _ in 0..tag_count {
            tags.push(take_utf8(bytes, &mut cursor, "export item tag")?);
        }
        let secret = take_vec(bytes, &mut cursor, "export item secret")?;
        items.push(PlainItem {
            kind,
            label,
            secret: SecretBytes::new(secret),
            tags,
        });
    }
    if cursor != bytes.len() {
        return Err(CoreError::Format("export payload trailing garbage".into()));
    }
    Ok(items)
}

fn write_len_bytes(out: &mut Vec<u8>, bytes: &[u8], overflow: &'static str) -> Result<()> {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| CoreError::Format(overflow.into()))?
            .to_le_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize, field: &'static str) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| CoreError::Format(format!("{field} offset overflow")))?;
    let raw: [u8; 2] = bytes
        .get(offset..end)
        .ok_or_else(|| CoreError::Format(format!("truncated {field}")))?
        .try_into()
        .map_err(|_| CoreError::Format(format!("{field} read error")))?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize, field: &'static str) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| CoreError::Format(format!("{field} offset overflow")))?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .ok_or_else(|| CoreError::Format(format!("truncated {field}")))?
        .try_into()
        .map_err(|_| CoreError::Format(format!("{field} read error")))?;
    Ok(u32::from_le_bytes(raw))
}

fn take_u16(bytes: &[u8], cursor: &mut usize, field: &'static str) -> Result<u16> {
    let value = read_u16(bytes, *cursor, field)?;
    *cursor = cursor
        .checked_add(2)
        .ok_or_else(|| CoreError::Format(format!("{field} cursor overflow")))?;
    Ok(value)
}

fn take_u32(bytes: &[u8], cursor: &mut usize, field: &'static str) -> Result<usize> {
    let value = read_u32(bytes, *cursor, field)?;
    *cursor = cursor
        .checked_add(4)
        .ok_or_else(|| CoreError::Format(format!("{field} cursor overflow")))?;
    usize::try_from(value).map_err(|_| CoreError::Format(format!("{field} length overflow")))
}

fn take_vec(bytes: &[u8], cursor: &mut usize, field: &'static str) -> Result<Vec<u8>> {
    let len = take_u32(bytes, cursor, field)?;
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| CoreError::Format(format!("{field} length overflow")))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| CoreError::Format(format!("truncated {field}")))?
        .to_vec();
    *cursor = end;
    Ok(value)
}

fn take_utf8(bytes: &[u8], cursor: &mut usize, field: &'static str) -> Result<String> {
    String::from_utf8(take_vec(bytes, cursor, field)?)
        .map_err(|_| CoreError::Format(format!("invalid {field} encoding")))
}

#[cfg(test)]
// REASON: these unit tests use explicit fixture assertions and panic closures
// to pin fail-closed behavior; production code has no clippy allowances.
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        item::{add, list, with_item, ItemKind, PlainItem},
        vault::engine::{create, lock, unlock, CreateVaultParams, UnlockParams},
    };
    use meissnerseal_security::secret_lifecycle::SecretBytes;

    const PASSWORD: &[u8] = b"core-10-vault-password-never-real";
    const EXPORT_PASSPHRASE: &[u8] = b"core-10-export-passphrase-never-real";
    const WRONG_EXPORT_PASSPHRASE: &[u8] = b"wrong-core-10-export-passphrase-never-real";

    fn unique_temp_vault_path(label: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir(); // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        path.push(format!(
            "meissnerseal-core-export-{label}-{}-{nanos}.msv",
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
        .expect("create export test vault");
        let session = unlock(UnlockParams {
            path: path.clone(),
            password: SecretBytes::new(PASSWORD.to_vec()),
        })
        .expect("unlock export test vault");
        (path, session)
    }

    fn plain_item(label: &str, secret: &[u8]) -> PlainItem {
        PlainItem {
            kind: ItemKind::SecureNote,
            label: label.to_string(),
            secret: SecretBytes::new(secret.to_vec()),
            tags: vec!["core10".to_string()],
        }
    }

    fn cleanup(path: &std::path::Path, session: VaultSession) {
        let _ = lock(session);
        let _ = std::fs::remove_file(path);
    }

    fn framed_bundle(version: u16, ciphertext_and_tag: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ARCEXP_MAGIC);
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&[0xa5; 16]);
        let kdf_params = [
            0x01, 0x00, // KDF_ARGON2ID_V1 fixture profile id
            0x00, 0x00, // minimal placeholder params for parser reject tests
        ];
        out.extend_from_slice(
            &u32::try_from(kdf_params.len())
                .expect("fixture KDF params length fits u32")
                .to_le_bytes(),
        );
        out.extend_from_slice(&kdf_params);
        out.extend_from_slice(&[0x5a; 24]);
        out.extend_from_slice(
            &u32::try_from(ciphertext_and_tag.len())
                .expect("fixture ciphertext length fits u32")
                .to_le_bytes(),
        );
        out.extend_from_slice(ciphertext_and_tag);
        out
    }

    fn assert_imported_item(session: &VaultSession, expected_label: &str, expected_secret: &[u8]) {
        let summaries = list(session).expect("imported item must be listed");
        let imported = summaries
            .iter()
            .find(|summary| summary.label == expected_label)
            .expect("imported summary must exist");
        with_item(session, imported.id, |view| {
            assert_eq!(view.label, expected_label);
            view.secret.with_secret(|secret| {
                assert_eq!(secret, expected_secret);
                Ok(())
            })
        })
        .expect("imported item decrypts only inside closure");
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn export_import_roundtrip_same_vault() {
        let (path, session) = unlocked_session("same-vault");

        add(
            &session,
            plain_item("same vault note", b"same vault secret"),
        )
        .expect("CORE-9 item add must work before CORE-10 export");
        let bundle = export(&session, EXPORT_PASSPHRASE)
            .expect("Phase 2: export must seal passphrase bundle");
        let imported_ids = import(&session, &bundle, EXPORT_PASSPHRASE)
            .expect("Phase 2: import must decrypt same-vault bundle");

        assert_eq!(imported_ids.len(), 1);
        assert_imported_item(&session, "same vault note", b"same vault secret");
        cleanup(&path, session);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn export_import_roundtrip_cross_vault() {
        let (source_path, source) = unlocked_session("cross-source");
        let (target_path, target) = unlocked_session("cross-target");

        add(
            &source,
            plain_item("cross vault note", b"cross vault secret"),
        )
        .expect("CORE-9 item add must work before CORE-10 export");
        let bundle = export(&source, EXPORT_PASSPHRASE)
            .expect("Phase 2: export must seal passphrase bundle");
        let imported_ids = import(&target, &bundle, EXPORT_PASSPHRASE)
            .expect("Phase 2: import must support cross-vault passphrase import");

        assert_eq!(imported_ids.len(), 1);
        assert_imported_item(&target, "cross vault note", b"cross vault secret");
        cleanup(&source_path, source);
        cleanup(&target_path, target);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn export_import_wrong_passphrase_rejects() {
        let (path, session) = unlocked_session("wrong-passphrase");

        add(&session, plain_item("wrong passphrase", b"must reject"))
            .expect("CORE-9 item add must work before CORE-10 export");
        let bundle = export(&session, EXPORT_PASSPHRASE)
            .expect("Phase 2: export must seal passphrase bundle");

        assert!(import(&session, &bundle, WRONG_EXPORT_PASSPHRASE).is_err());
        cleanup(&path, session);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn import_rejects_wrong_magic() {
        let (path, session) = unlocked_session("wrong-magic");
        let mut bundle = framed_bundle(ARCEXP_VERSION_V1, &[0x7b; 16]);
        bundle
            .get_mut(0..8)
            .expect("fixture magic range")
            .copy_from_slice(b"NOTEXP\x01\0");

        assert!(import(&session, &bundle, EXPORT_PASSPHRASE).is_err());
        cleanup(&path, session);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn import_rejects_unknown_version() {
        let (path, session) = unlocked_session("unknown-version");
        let bundle = framed_bundle(0xFFFF, &[0x7b; 16]);

        assert!(import(&session, &bundle, EXPORT_PASSPHRASE).is_err());
        cleanup(&path, session);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn import_rejects_truncated_bundle() {
        let (path, session) = unlocked_session("truncated");
        let bundle = &ARCEXP_MAGIC[..4];

        assert!(import(&session, bundle, EXPORT_PASSPHRASE).is_err());
        cleanup(&path, session);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn import_rejects_tampered_ciphertext() {
        let (path, session) = unlocked_session("tamper");

        add(&session, plain_item("tamper export", b"tamper secret"))
            .expect("CORE-9 item add must work before CORE-10 export");
        let mut bundle = export(&session, EXPORT_PASSPHRASE)
            .expect("Phase 2: export must seal passphrase bundle");
        let last = bundle
            .last_mut()
            .expect("exported bundle must contain ciphertext");
        *last ^= 0xFF;

        assert!(import(&session, &bundle, EXPORT_PASSPHRASE).is_err());
        cleanup(&path, session);
    }
}
