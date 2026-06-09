//! Item store API contracts.

use arcanum_crypto::aead::{decrypt, encrypt, Ciphertext};
use arcanum_crypto::types::{AeadKey, XChaCha20Nonce};
use arcanum_security::secret_lifecycle::SecretBytes;
use zeroize::Zeroize;

use crate::{
    error::{CoreError, Result},
    item::model::{ItemId, ItemKind, ItemSummary, PlainItem, PlainItemView},
    vault::engine::{persist_vault_mutation_v2, record_frame_len_at, VaultSession},
    vault::format::{
        build_aad, open_sealed_record_table_v2, parse_header, parse_item_record_frame_envelope,
        parse_record_frame, sealed_record_table_padded_plaintext_len,
        serialize_item_record_frame_envelope, serialize_prefix, serialize_record_frame,
        serialize_sealed_record_table_v2, ItemRecordFrameEnvelope, RecordFrame, RecordTableEntry,
        VaultHeader, FORMAT_VERSION, HEADER_MIN_LEN, RECORD_KIND_ITEM, RECORD_KIND_TOMBSTONE,
    },
};

// Byte offsets within the 26-byte vault file prefix (vault_format_v1.md §2).
const PREFIX_HEADER_LEN_OFFSET: usize = 10;
const PREFIX_RECORD_TABLE_LEN_OFFSET: usize = 14;

// Sealed-table section framing overhead: sealed_table_len:u32 + nonce[24] + tag.
const SEALED_TABLE_SECTION_OVERHEAD: usize = 4 + 24 + arcanum_crypto::aead::TAG_LEN;

// ── internal helpers ─────────────────────────────────────────────────────────

/// A vault loaded from disk together with its authenticated V2 record table.
struct LoadedVault {
    bytes: Vec<u8>,
    header: VaultHeader,
    wrk_frame_offset: usize,
    wrk_frame_len: usize,
    entries: Vec<RecordTableEntry>,
}

/// Item payload decoded from an authenticated item frame. Owns its plaintext
/// only for the lifetime of one `with_item`/`list` call; `secret` zeroizes on
/// drop.
struct DecodedItem {
    kind: ItemKind,
    label: String,
    tags: Vec<String>,
    secret: SecretBytes,
}

/// A record staged for the rewritten table; `frame_bytes` is its full §6 frame.
struct PendingRecord {
    record_id: [u8; 16],
    record_kind: u16,
    revision_id: [u8; 16],
    frame_bytes: Vec<u8>,
}

fn fresh_id() -> Result<[u8; 16]> {
    arcanum_crypto::rng::random_bytes(16)
        .try_into()
        .map_err(|_| CoreError::Crypto)
}

fn read_prefix_u32(bytes: &[u8], offset: usize) -> Result<usize> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| CoreError::Format("vault prefix offset overflow".into()))?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| CoreError::Format("truncated vault prefix".into()))?;
    let array: [u8; 4] = raw
        .try_into()
        .map_err(|_| CoreError::Format("prefix u32 read error".into()))?;
    usize::try_from(u32::from_le_bytes(array))
        .map_err(|_| CoreError::Format("prefix u32 overflow".into()))
}

fn id_hex(id: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(32);
    for byte in id {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Read the vault file, parse the header, and open the MEK-sealed table.
fn load_vault(session: &VaultSession) -> Result<LoadedVault> {
    let bytes = std::fs::read(session.path())?;
    let header = parse_header(&bytes)?;
    let header_len = read_prefix_u32(&bytes, PREFIX_HEADER_LEN_OFFSET)?;
    let table_len = read_prefix_u32(&bytes, PREFIX_RECORD_TABLE_LEN_OFFSET)?;
    let wrk_frame_offset = HEADER_MIN_LEN
        .checked_add(header_len)
        .ok_or_else(|| CoreError::Format("WRK frame offset overflow".into()))?;
    let wrk_frame_len = usize::try_from(record_frame_len_at(&bytes, wrk_frame_offset)?)
        .map_err(|_| CoreError::Format("WRK frame length overflow".into()))?;
    let table_offset = wrk_frame_offset
        .checked_add(wrk_frame_len)
        .ok_or_else(|| CoreError::Format("record table offset overflow".into()))?;
    let entries = open_sealed_record_table_v2(
        &bytes,
        table_offset,
        table_len,
        &session.keys().metadata_key,
        &header.vault_id,
        header.schema_profile,
        wrk_frame_offset,
        bytes.len(),
    )?;
    Ok(LoadedVault {
        bytes,
        header,
        wrk_frame_offset,
        wrk_frame_len,
        entries,
    })
}

/// Canonical 74-byte per-record AAD (§7) for an item or tombstone record.
fn item_record_aad(
    header: &VaultHeader,
    record_id: &[u8; 16],
    revision_id: &[u8; 16],
    record_kind: u16,
) -> [u8; 74] {
    build_aad(
        &header.vault_id,
        header.format_version,
        header.schema_profile,
        header.aead_profile,
        header.kdf_profile,
        header.pqc_profile,
        record_id,
        revision_id,
        record_kind,
    )
}

fn u32_len(value: usize, error: &'static str) -> Result<u32> {
    u32::try_from(value).map_err(|_| CoreError::Format(error.into()))
}

/// Serialize the item plaintext (kind + encrypted-where-possible metadata +
/// secret) that is sealed under the REK. Caller MUST zeroize the returned buffer.
fn serialize_item_payload(item: &PlainItem) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&item.kind.as_u16().to_le_bytes());

    let label = item.label.as_bytes();
    out.extend_from_slice(&u32_len(label.len(), "item label length overflow")?.to_le_bytes());
    out.extend_from_slice(label);

    out.extend_from_slice(&u32_len(item.tags.len(), "item tag count overflow")?.to_le_bytes());
    for tag in &item.tags {
        let tag = tag.as_bytes();
        out.extend_from_slice(&u32_len(tag.len(), "item tag length overflow")?.to_le_bytes());
        out.extend_from_slice(tag);
    }

    item.secret.with_secret(|secret| -> Result<()> {
        out.extend_from_slice(&u32_len(secret.len(), "item secret length overflow")?.to_le_bytes());
        out.extend_from_slice(secret);
        Ok(())
    })?;
    Ok(out)
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<usize> {
    let end = cursor
        .checked_add(4)
        .ok_or_else(|| CoreError::Format("item payload length overflow".into()))?;
    let raw = bytes
        .get(*cursor..end)
        .ok_or_else(|| CoreError::Format("truncated item payload".into()))?;
    let array: [u8; 4] = raw
        .try_into()
        .map_err(|_| CoreError::Format("item payload u32 read error".into()))?;
    *cursor = end;
    usize::try_from(u32::from_le_bytes(array))
        .map_err(|_| CoreError::Format("item payload field overflow".into()))
}

fn take_bytes<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| CoreError::Format("item payload length overflow".into()))?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or_else(|| CoreError::Format("truncated item payload".into()))?;
    *cursor = end;
    Ok(slice)
}

/// Inverse of [`serialize_item_payload`] over authenticated plaintext.
fn deserialize_item_payload(bytes: &[u8]) -> Result<DecodedItem> {
    let mut cursor = 0usize;

    let kind_raw = {
        let raw: [u8; 2] = take_bytes(bytes, &mut cursor, 2)?
            .try_into()
            .map_err(|_| CoreError::Format("item kind read error".into()))?;
        u16::from_le_bytes(raw)
    };
    let kind = ItemKind::from_u16(kind_raw)?;

    let label_len = take_u32(bytes, &mut cursor)?;
    let label = String::from_utf8(take_bytes(bytes, &mut cursor, label_len)?.to_vec())
        .map_err(|_| CoreError::Format("invalid item label encoding".into()))?;

    let tag_count = take_u32(bytes, &mut cursor)?;
    let mut tags = Vec::new();
    for _ in 0..tag_count {
        let tag_len = take_u32(bytes, &mut cursor)?;
        let tag = String::from_utf8(take_bytes(bytes, &mut cursor, tag_len)?.to_vec())
            .map_err(|_| CoreError::Format("invalid item tag encoding".into()))?;
        tags.push(tag);
    }

    let secret_len = take_u32(bytes, &mut cursor)?;
    let secret = SecretBytes::new(take_bytes(bytes, &mut cursor, secret_len)?.to_vec());

    if cursor != bytes.len() {
        return Err(CoreError::Format("trailing item payload garbage".into()));
    }
    Ok(DecodedItem {
        kind,
        label,
        tags,
        secret,
    })
}

/// Assemble one §6 record frame holding `ciphertext` as its body.
fn build_record_frame(
    record_id: &[u8; 16],
    revision_id: &[u8; 16],
    ciphertext: Vec<u8>,
    aad: &[u8; 74],
) -> Result<Vec<u8>> {
    let ciphertext_len = u32_len(ciphertext.len(), "item frame ciphertext length overflow")?;
    let frame = RecordFrame {
        frame_version: FORMAT_VERSION,
        record_id: *record_id,
        revision_id: *revision_id,
        // The §6 nonce field is structural; item AEAD nonces live in the envelope.
        nonce: arcanum_crypto::rng::random_nonce_xchacha20(),
        ciphertext_len,
        ciphertext,
    };
    serialize_record_frame(&frame, aad)
}

/// Build a fresh item frame: encrypt the payload under a fresh REK, wrap the REK
/// under the IKWK, and serialize the wrapped-REK envelope into a §6 frame. Both
/// AEAD operations bind the same canonical §7 AAD.
fn build_item_frame(
    item: &PlainItem,
    item_wrap_key: &AeadKey,
    header: &VaultHeader,
    record_id: &[u8; 16],
    revision_id: &[u8; 16],
) -> Result<Vec<u8>> {
    let aad = item_record_aad(header, record_id, revision_id, RECORD_KIND_ITEM);

    let mut payload_plain = serialize_item_payload(item)?;
    let mut rek_bytes: [u8; 32] = arcanum_crypto::rng::random_bytes(32)
        .try_into()
        .map_err(|_| CoreError::Crypto)?;
    let rek = AeadKey::from_bytes(rek_bytes);
    rek_bytes.zeroize();

    let payload_result = encrypt(&rek, &payload_plain, &aad);
    payload_plain.zeroize();
    let (payload_ct, payload_nonce) = payload_result.map_err(|_| CoreError::Crypto)?;

    let (wrapped_rek_ct, rek_wrap_nonce) =
        encrypt(item_wrap_key, rek.as_slice(), &aad).map_err(|_| CoreError::Crypto)?;
    drop(rek); // ZeroizeOnDrop clears the REK bytes.

    let envelope = ItemRecordFrameEnvelope {
        rek_wrap_nonce: *rek_wrap_nonce.as_bytes(),
        wrapped_rek: wrapped_rek_ct.as_ref().to_vec(),
        payload_nonce: *payload_nonce.as_bytes(),
        encrypted_payload: payload_ct.as_ref().to_vec(),
    };
    let envelope_bytes = serialize_item_record_frame_envelope(&envelope)?;
    build_record_frame(record_id, revision_id, envelope_bytes, &aad)
}

/// Copy an existing record's frame bytes out of the loaded vault.
fn existing_frame_bytes(loaded: &LoadedVault, entry: &RecordTableEntry) -> Result<Vec<u8>> {
    let start = usize::try_from(entry.frame_offset)
        .map_err(|_| CoreError::Format("frame offset overflow".into()))?;
    let len = usize::try_from(entry.frame_len)
        .map_err(|_| CoreError::Format("frame length overflow".into()))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| CoreError::Format("frame bounds overflow".into()))?;
    loaded
        .bytes
        .get(start..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| CoreError::Format("frame out of bounds".into()))
}

/// Authenticate and decrypt one live item entry into owned, short-lived plaintext.
fn read_item(
    session: &VaultSession,
    loaded: &LoadedVault,
    entry: &RecordTableEntry,
) -> Result<DecodedItem> {
    let start = usize::try_from(entry.frame_offset)
        .map_err(|_| CoreError::Format("frame offset overflow".into()))?;
    let frame_slice = loaded
        .bytes
        .get(start..)
        .ok_or_else(|| CoreError::Format("frame offset out of bounds".into()))?;
    let frame = parse_record_frame(frame_slice, entry.frame_len)?;

    // Substitution defense: the MEK-sealed table entry and the frame must agree.
    if frame.record_id != entry.record_id || frame.revision_id != entry.revision_id {
        return Err(CoreError::Auth);
    }

    let envelope = parse_item_record_frame_envelope(&frame.ciphertext)?;
    let aad = item_record_aad(
        &loaded.header,
        &entry.record_id,
        &entry.revision_id,
        RECORD_KIND_ITEM,
    );

    // Unwrap the REK under the IKWK.
    let rek_wrap_nonce = XChaCha20Nonce::from_bytes(envelope.rek_wrap_nonce);
    let wrapped_rek = Ciphertext::from(envelope.wrapped_rek);
    let rek_plain = decrypt(
        &session.keys().item_wrap_key,
        &rek_wrap_nonce,
        &wrapped_rek,
        &aad,
    )
    .map_err(|_| CoreError::Auth)?;
    let mut rek_bytes = <[u8; 32]>::try_from(rek_plain.as_ref()).map_err(|_| CoreError::Crypto)?;
    drop(rek_plain);
    let rek = AeadKey::from_bytes(rek_bytes);
    rek_bytes.zeroize();

    // Decrypt the payload under the REK.
    let payload_nonce = XChaCha20Nonce::from_bytes(envelope.payload_nonce);
    let payload_ct = Ciphertext::from(envelope.encrypted_payload);
    let payload_plain =
        decrypt(&rek, &payload_nonce, &payload_ct, &aad).map_err(|_| CoreError::Auth)?;
    drop(rek);

    let decoded = deserialize_item_payload(payload_plain.as_ref())?;
    drop(payload_plain);
    Ok(decoded)
}

/// Re-seal the table over `records`, recompute frame offsets, and rewrite the
/// vault through the V2 crash-safe mutation path.
fn rewrite_vault(
    session: &VaultSession,
    loaded: &LoadedVault,
    records: &[PendingRecord],
) -> Result<()> {
    let header_bytes = loaded
        .bytes
        .get(HEADER_MIN_LEN..loaded.wrk_frame_offset)
        .ok_or_else(|| CoreError::Format("header section out of bounds".into()))?;
    let wrk_end = loaded
        .wrk_frame_offset
        .checked_add(loaded.wrk_frame_len)
        .ok_or_else(|| CoreError::Format("WRK frame bounds overflow".into()))?;
    let wrk_bytes = loaded
        .bytes
        .get(loaded.wrk_frame_offset..wrk_end)
        .ok_or_else(|| CoreError::Format("WRK frame out of bounds".into()))?;

    // The sealed-table section length depends only on the entry count, so frame
    // offsets can be computed before the table is sealed.
    let padded_plaintext_len = sealed_record_table_padded_plaintext_len(records.len())?;
    let table_section_len = SEALED_TABLE_SECTION_OVERHEAD
        .checked_add(padded_plaintext_len)
        .ok_or_else(|| CoreError::Format("sealed table length overflow".into()))?;

    let mut next_offset = wrk_end
        .checked_add(table_section_len)
        .ok_or_else(|| CoreError::Format("frame offset overflow".into()))?;

    let mut entries = Vec::with_capacity(records.len());
    let mut frames_concat = Vec::new();
    for record in records {
        let frame_len = u32_len(record.frame_bytes.len(), "frame length overflow")?;
        entries.push(RecordTableEntry {
            record_id: record.record_id,
            record_kind: record.record_kind,
            revision_id: record.revision_id,
            frame_offset: u64::try_from(next_offset)
                .map_err(|_| CoreError::Format("frame offset overflow".into()))?,
            frame_len,
        });
        frames_concat.extend_from_slice(&record.frame_bytes);
        next_offset = next_offset
            .checked_add(record.frame_bytes.len())
            .ok_or_else(|| CoreError::Format("frame offset overflow".into()))?;
    }

    let table_bytes = serialize_sealed_record_table_v2(
        &entries,
        &session.keys().metadata_key,
        &loaded.header.vault_id,
        loaded.header.schema_profile,
    )?;
    if table_bytes.len() != table_section_len {
        return Err(CoreError::Format(
            "sealed table section length mismatch".into(),
        ));
    }

    let body_len = wrk_bytes
        .len()
        .checked_add(table_bytes.len())
        .and_then(|len| len.checked_add(frames_concat.len()))
        .ok_or_else(|| CoreError::Format("body length overflow".into()))?;
    let prefix = serialize_prefix(
        FORMAT_VERSION,
        u32_len(header_bytes.len(), "header length overflow")?,
        u32_len(table_bytes.len(), "record table length overflow")?,
        u64::try_from(body_len).map_err(|_| CoreError::Format("body length overflow".into()))?,
    )?;

    let capacity = prefix
        .len()
        .saturating_add(header_bytes.len())
        .saturating_add(body_len);
    let mut vault_bytes = Vec::with_capacity(capacity);
    vault_bytes.extend_from_slice(&prefix);
    vault_bytes.extend_from_slice(header_bytes);
    vault_bytes.extend_from_slice(wrk_bytes);
    vault_bytes.extend_from_slice(&table_bytes);
    vault_bytes.extend_from_slice(&frames_concat);

    let unique_seed = fresh_id()?;
    persist_vault_mutation_v2(session.path(), &vault_bytes, &unique_seed)
}

/// Stage the surviving records, replacing the record at `position` (if any) with
/// `replacement`; entries other than `position` keep their frames verbatim.
fn stage_records(
    loaded: &LoadedVault,
    position: Option<usize>,
    replacement: Option<PendingRecord>,
) -> Result<Vec<PendingRecord>> {
    let mut replacement = replacement;
    let mut records = Vec::with_capacity(loaded.entries.len().saturating_add(1));
    for (index, entry) in loaded.entries.iter().enumerate() {
        if position == Some(index) {
            let pending = replacement
                .take()
                .ok_or_else(|| CoreError::InvalidState("missing record replacement".into()))?;
            records.push(pending);
        } else {
            records.push(PendingRecord {
                record_id: entry.record_id,
                record_kind: entry.record_kind,
                revision_id: entry.revision_id,
                frame_bytes: existing_frame_bytes(loaded, entry)?,
            });
        }
    }
    if let Some(pending) = replacement.take() {
        // Append-only case (no position matched): used by `add`.
        records.push(pending);
    }
    Ok(records)
}

/// Locate the table index of a live (non-tombstone) item by id.
fn live_item_position(loaded: &LoadedVault, item_id: &ItemId) -> Option<usize> {
    loaded
        .entries
        .iter()
        .position(|entry| entry.record_id == *item_id && entry.record_kind == RECORD_KIND_ITEM)
}

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
pub fn add(session: &VaultSession, item: PlainItem) -> Result<ItemId> {
    let loaded = load_vault(session)?;
    let record_id = fresh_id()?;
    let revision_id = fresh_id()?;

    let frame_bytes = build_item_frame(
        &item,
        &session.keys().item_wrap_key,
        &loaded.header,
        &record_id,
        &revision_id,
    )?;
    drop(item); // plaintext consumed; SecretBytes zeroizes on drop.

    let records = stage_records(
        &loaded,
        None,
        Some(PendingRecord {
            record_id,
            record_kind: RECORD_KIND_ITEM,
            revision_id,
            frame_bytes,
        }),
    )?;
    rewrite_vault(session, &loaded, &records)?;
    Ok(record_id)
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
pub fn list(session: &VaultSession) -> Result<Vec<ItemSummary>> {
    let loaded = load_vault(session)?;
    let mut summaries = Vec::new();
    for entry in &loaded.entries {
        // Tombstones (0x0006) and any non-item record kinds are excluded.
        if entry.record_kind != RECORD_KIND_ITEM {
            continue;
        }
        let decoded = read_item(session, &loaded, entry)?;
        summaries.push(ItemSummary {
            id: entry.record_id,
            kind: decoded.kind,
            label: decoded.label,
            tags: decoded.tags,
        });
        // decoded.secret is dropped (zeroized) here; never placed in a summary.
    }
    Ok(summaries)
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
pub fn with_item<F, R>(session: &VaultSession, item_id: ItemId, f: F) -> Result<R>
where
    F: FnOnce(&PlainItemView<'_>) -> Result<R>,
{
    let loaded = load_vault(session)?;
    let entry = loaded
        .entries
        .iter()
        .find(|entry| entry.record_id == item_id && entry.record_kind == RECORD_KIND_ITEM)
        .ok_or_else(|| CoreError::NotFound(id_hex(&item_id)))?;
    let decoded = read_item(session, &loaded, entry)?;

    // The view borrows `decoded`; no owned plaintext can escape the closure (G-02).
    let view = PlainItemView {
        kind: &decoded.kind,
        label: &decoded.label,
        tags: &decoded.tags,
        secret: &decoded.secret,
    };
    f(&view)
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
pub fn update(session: &VaultSession, item_id: ItemId, item: PlainItem) -> Result<()> {
    let loaded = load_vault(session)?;
    let position = live_item_position(&loaded, &item_id)
        .ok_or_else(|| CoreError::NotFound(id_hex(&item_id)))?;

    // Preserve record_id; a fresh revision_id re-binds the AAD so the previous
    // revision's REK/AAD cannot authenticate the replacement frame.
    let revision_id = fresh_id()?;
    let frame_bytes = build_item_frame(
        &item,
        &session.keys().item_wrap_key,
        &loaded.header,
        &item_id,
        &revision_id,
    )?;
    drop(item);

    let records = stage_records(
        &loaded,
        Some(position),
        Some(PendingRecord {
            record_id: item_id,
            record_kind: RECORD_KIND_ITEM,
            revision_id,
            frame_bytes,
        }),
    )?;
    rewrite_vault(session, &loaded, &records)
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
pub fn delete(session: &VaultSession, item_id: ItemId) -> Result<()> {
    let loaded = load_vault(session)?;
    let position = match live_item_position(&loaded, &item_id) {
        Some(position) => position,
        None => {
            // Idempotent: an already-tombstoned id is treated as deleted.
            let already_tombstoned = loaded.entries.iter().any(|entry| {
                entry.record_id == item_id && entry.record_kind == RECORD_KIND_TOMBSTONE
            });
            if already_tombstoned {
                return Ok(());
            }
            return Err(CoreError::NotFound(id_hex(&item_id)));
        }
    };

    let revision_id = fresh_id()?;
    let aad = item_record_aad(
        &loaded.header,
        &item_id,
        &revision_id,
        RECORD_KIND_TOMBSTONE,
    );
    let tombstone_frame = build_record_frame(&item_id, &revision_id, Vec::new(), &aad)?;

    let records = stage_records(
        &loaded,
        Some(position),
        Some(PendingRecord {
            record_id: item_id,
            record_kind: RECORD_KIND_TOMBSTONE,
            revision_id,
            frame_bytes: tombstone_frame,
        }),
    )?;
    rewrite_vault(session, &loaded, &records)
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
