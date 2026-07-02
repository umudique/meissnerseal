// SPDX-License-Identifier: Apache-2.0
//! Integration known-answer tests for meissnerseal-core vault parsing (finding A1).
//!
//! Deserializes `test-vectors/*.json` and drives the real public
//! `vault::format` API: positives must round-trip to the documented fields and
//! AAD bytes; negatives must be rejected (fail-closed). The negative AEAD case
//! drives `meissnerseal_crypto::aead::decrypt`. Vectors carry no real secrets and no
//! plaintext is printed; failure messages reference only the case id.

// REASON: KAT-consumption test over fixed, non-secret vectors. Indexing,
// unchecked arithmetic, casts, and expect/panic/unwrap are acceptable in this
// test-only code, which never ships in a release binary.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]

use meissnerseal_core::keys::hierarchy::{
    derive_master_unlock_key_with_header_params, derive_subkeys, UnlockedKeys,
};
use meissnerseal_core::vault::format::{
    build_aad, open_sealed_record_table_v2, parse_header, parse_kdf_profile_params,
    ARGON2_VERSION_0X13, HEADER_MIN_LEN, KDF_ARGON2ID_V1, SCHEMA_MEISSNER_RECORDS_V2,
};
use meissnerseal_core::{
    error::CoreError,
    export::{export, import},
    item::{add, list, with_item, ItemKind, PlainItem},
    vault::engine::{CreateVaultParams, Locked, UnlockParams, Unlocked, Vault},
};
use meissnerseal_crypto::types::{AeadKey, HkdfPrk, Key, MasterUnlockKey};
use meissnerseal_security::secret_lifecycle::SecretBytes;
use serde_json::Value;

// ── helpers ──────────────────────────────────────────────────────────────────

fn load(name: &str) -> Value {
    let text = match name {
        "vault_kdf_param_tlv_v1.json" => {
            include_str!("../../../test-vectors/vault_kdf_param_tlv_v1.json")
        }
        "vault_kdf_v1.json" => include_str!("../../../test-vectors/vault_kdf_v1.json"),
        "vault_format_v1.json" => include_str!("../../../test-vectors/vault_format_v1.json"),
        "vault_format_struct_v1.json" => {
            include_str!("../../../test-vectors/vault_format_struct_v1.json")
        }
        "vault_format_negative_v1.json" => {
            include_str!("../../../test-vectors/vault_format_negative_v1.json")
        }
        "export_import_v1.json" => include_str!("../../../test-vectors/export_import_v1.json"),
        _ => panic!("unknown vector file {name}"),
    };
    serde_json::from_str(text).expect("valid JSON vector file")
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "hex string must have even length"
    );
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).expect("hex digit");
            let lo = (pair[1] as char).to_digit(16).expect("hex digit");
            ((hi << 4) | lo) as u8
        })
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    <[u8; N]>::try_from(unhex(s).as_slice()).expect("fixed-width hex field")
}

fn find<'a>(v: &'a Value, id: &str) -> &'a Value {
    v["cases"]
        .as_array()
        .expect("cases array")
        .iter()
        .find(|c| c["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing case {id}"))
}

fn u16_from_hex_tag(s: &str) -> u16 {
    u16::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex tag")
}

fn kdf_profile_value_from_vector() -> Vec<u8> {
    let v = load("vault_kdf_param_tlv_v1.json");
    let c = find(&v, "kdf-param-tlv-argon2id-v1");
    unhex(c["expected"]["kdf_profile_value_hex"].as_str().unwrap())
}

fn set_kdf_params_len(block: &mut [u8], params_len: u32) {
    block[2..6].copy_from_slice(&params_len.to_le_bytes());
}

fn kdf_params_len(block: &[u8]) -> usize {
    u32::from_le_bytes(block[2..6].try_into().unwrap()) as usize
}

fn find_kdf_param_tlv(block: &[u8], wanted_tag: u16) -> Option<(usize, usize)> {
    let params_len = kdf_params_len(block);
    let mut cursor = 6usize;
    let end = 6 + params_len;
    while cursor + 4 <= end {
        let tag = u16::from_le_bytes(block[cursor..cursor + 2].try_into().unwrap());
        let len = u16::from_le_bytes(block[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
        if cursor + 4 + len > end {
            return None;
        }
        if tag == wanted_tag {
            return Some((cursor, 4 + len));
        }
        cursor += 4 + len;
    }
    None
}

fn remove_kdf_param_tlv(block: &mut Vec<u8>, tag: u16) {
    let (offset, len) = find_kdf_param_tlv(block, tag).expect("TLV tag present");
    block.drain(offset..offset + len);
    let next_params_len = kdf_params_len(block) - len;
    set_kdf_params_len(block, next_params_len as u32);
}

fn duplicate_kdf_param_tlv(block: &mut Vec<u8>, tag: u16) {
    let (offset, len) = find_kdf_param_tlv(block, tag).expect("TLV tag present");
    let tlv = block[offset..offset + len].to_vec();
    block.extend_from_slice(&tlv);
    let next_params_len = kdf_params_len(block) + len;
    set_kdf_params_len(block, next_params_len as u32);
}

fn subkey_derivation_case() -> Value {
    find(&load("vault_kdf_v1.json"), "subkey-derivation").clone()
}

fn derive_vector_unlocked_keys() -> UnlockedKeys {
    let c = subkey_derivation_case();
    let root_prk = HkdfPrk::from_bytes(arr::<32>(c["inputs"]["root_prk"].as_str().unwrap()));
    let vault_id = arr::<16>(c["inputs"]["vault_id"].as_str().unwrap());
    let aead_id = c["inputs"]["aead_id"].as_u64().unwrap() as u16;

    derive_subkeys(&root_prk, &vault_id, aead_id)
        .expect("all seven HKDF registry subkeys must derive")
}

fn vector_subkeys(keys: &UnlockedKeys) -> [&Key<32>; 7] {
    [
        &keys.item_wrap_key,
        &keys.metadata_key,
        &keys.audit_key,
        &keys.sync_envelope_key,
        &keys.device_enrollment_key,
        &keys.recovery_wrapping_key,
        &keys.export_key,
    ]
}

const TEST_VAULT_PASSWORD: &[u8] = b"vectors-vault-password-never-real";

fn unique_temp_vault_path(label: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir(); // nosemgrep: rust.lang.security.temp-dir.temp-dir
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    path.push(format!(
        "meissnerseal-core-vectors-{label}-{}-{nanos}.msv",
        std::process::id()
    ));
    path
}

fn unlocked_session(label: &str) -> (std::path::PathBuf, Vault<Unlocked>) {
    let path = unique_temp_vault_path(label);
    let _ = std::fs::remove_file(&path);
    Vault::<Locked>::create(CreateVaultParams {
        path: path.clone(),
        password: SecretBytes::new(TEST_VAULT_PASSWORD.to_vec()),
    })
    .expect("create vector test vault");
    let session = Vault::<Locked>::open(path.clone())
        .expect("open locked vault")
        .unlock(UnlockParams {
            path: path.clone(),
            password: SecretBytes::new(TEST_VAULT_PASSWORD.to_vec()),
        })
        .expect("unlock vector test vault");
    (path, session)
}

fn cleanup(path: &std::path::Path, session: Vault<Unlocked>) {
    let _ = session.lock();
    let _ = std::fs::remove_file(path);
}

fn plain_item_from_vector(item: &Value) -> PlainItem {
    PlainItem {
        kind: parse_item_kind(item["kind"].as_str().expect("item kind")),
        label: item["label"].as_str().expect("item label").to_string(),
        secret: SecretBytes::new(unhex(item["secret_hex"].as_str().expect("item secret hex"))),
        tags: item["tags"]
            .as_array()
            .expect("item tags array")
            .iter()
            .map(|tag| tag.as_str().expect("tag string").to_string())
            .collect(),
    }
}

fn parse_item_kind(kind: &str) -> ItemKind {
    match kind {
        "Password" => ItemKind::Password,
        "SeedPhrase" => ItemKind::SeedPhrase,
        "SshPrivateKey" => ItemKind::SshPrivateKey,
        "ApiToken" => ItemKind::ApiToken,
        "SecureNote" => ItemKind::SecureNote,
        _ => panic!("unknown vector item kind {kind}"),
    }
}

fn plain_note(label: &str, secret: &[u8]) -> PlainItem {
    PlainItem {
        kind: ItemKind::SecureNote,
        label: label.to_string(),
        secret: SecretBytes::new(secret.to_vec()),
        tags: vec!["vectors".to_string()],
    }
}

fn assert_imported_items(session: &Vault<Unlocked>, expected_items: &[Value]) {
    let summaries = list(session).expect("imported items must be listed");
    assert_eq!(
        summaries.len(),
        expected_items.len(),
        "imported item count must match vector"
    );
    for expected in expected_items {
        let expected_label = expected["label"].as_str().expect("expected label");
        let expected_tags: Vec<String> = expected["tags"]
            .as_array()
            .expect("expected tags")
            .iter()
            .map(|tag| tag.as_str().expect("tag string").to_string())
            .collect();
        let expected_secret = unhex(expected["secret_hex"].as_str().expect("expected secret"));
        let imported = summaries
            .iter()
            .find(|summary| summary.label == expected_label)
            .unwrap_or_else(|| panic!("missing imported summary for label {expected_label}"));
        with_item(session, imported.id, |view| {
            assert_eq!(view.label, expected_label);
            assert_eq!(view.tags, expected_tags);
            view.secret.with_secret(|secret| {
                assert_eq!(secret, expected_secret.as_slice());
            });
            Ok(())
        })
        .expect("imported item decrypts only inside closure");
    }
}

// ── vault_format_v1.json — canonical 79-byte AAD construction (§7) ───────────

#[test]
fn vault_format_v1_aad_vectors() {
    let v = load("vault_format_v1.json");
    for c in v["cases"].as_array().expect("cases") {
        let id = c["id"].as_str().expect("id");
        let i = &c["inputs"];
        let vault_id = arr::<16>(i["vault_id"].as_str().unwrap());
        let record_id = arr::<16>(i["record_id"].as_str().unwrap());
        let revision_id = arr::<16>(i["revision_id"].as_str().unwrap());
        let aad = build_aad(
            &vault_id,
            i["format_version"].as_u64().unwrap() as u16,
            i["schema_profile"].as_u64().unwrap() as u16,
            i["aead_profile"].as_u64().unwrap() as u16,
            i["kdf_profile"].as_u64().unwrap() as u16,
            i["pqc_profile"].as_u64().unwrap() as u16,
            &record_id,
            &revision_id,
            i["record_kind"].as_u64().unwrap() as u16,
        );
        let expected = unhex(c["expected"]["aad_hex"].as_str().unwrap());
        assert_eq!(aad.as_slice(), expected.as_slice(), "case {id}: AAD bytes");
        assert_eq!(aad.len(), 79, "case {id}: AAD length");
    }
}

// ── vault_format_struct_v1.json — V2 fixed-WRK + MEK-sealed record table ──────

/// Read a little-endian `u32` at `offset` from a vault blob, as a `usize`.
fn read_u32_at(bytes: &[u8], offset: usize) -> usize {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}

/// Total byte length of the self-describing record frame starting at `offset`
/// (§6: version || record_id || revision_id || aead_profile || nonce_len ||
/// nonce || aad_len || aad || ciphertext_len || ciphertext). Used to skip the
/// fixed-position WrappedRootKey frame and locate the sealed table section.
// SHADOW PARSER: this helper duplicates production frame-layout knowledge in
// test code. It must stay in sync with the real record-frame boundary or the
// section_offset fed into open_sealed_record_table_v2 can become misleading and
// make coverage look stronger than it is.
fn record_frame_len_at(bytes: &[u8], offset: usize) -> usize {
    let nonce_len = bytes[offset + 2 + 16 + 16 + 2] as usize;
    let aad_len_offset = offset + 2 + 16 + 16 + 2 + 1 + nonce_len;
    let aad_len = read_u32_at(bytes, aad_len_offset);
    let ciphertext_len_offset = aad_len_offset + 4 + aad_len;
    let ciphertext_len = read_u32_at(bytes, ciphertext_len_offset);
    ciphertext_len_offset + 4 + ciphertext_len - offset
}

#[test]
#[allow(clippy::cognitive_complexity)]
fn vault_format_struct_v1_vectors() {
    let v = load("vault_format_struct_v1.json");
    for id in ["v2-empty-table-fixed-wrk", "v2-multi-entry-sealed-table"] {
        let c = find(&v, id);
        let blob = unhex(c["expected"]["vault_file_hex"].as_str().unwrap());
        let mek = AeadKey::from_bytes(arr::<32>(
            c["inputs"]["metadata_encryption_key"].as_str().unwrap(),
        ));

        // Header parses as V2 and round-trips the vault_id.
        let header = parse_header(&blob).unwrap_or_else(|_| panic!("{id}: header must parse"));
        assert_eq!(
            header.schema_profile, SCHEMA_MEISSNER_RECORDS_V2,
            "{id}: schema_profile must be V2"
        );
        assert_eq!(
            header.vault_id,
            arr::<16>(c["inputs"]["vault_id"].as_str().unwrap()),
            "{id}: vault_id"
        );

        // The WrappedRootKey frame sits at the fixed V2 offset HEADER_MIN_LEN +
        // header_len; the sealed table section follows it.
        let header_len = read_u32_at(&blob, 10);
        let wrk_frame_offset = HEADER_MIN_LEN + header_len;
        assert_eq!(
            wrk_frame_offset,
            c["expected"]["wrk_frame_offset"].as_u64().unwrap() as usize,
            "{id}: fixed WRK frame offset"
        );
        let section_offset = wrk_frame_offset + record_frame_len_at(&blob, wrk_frame_offset);
        let section_len = read_u32_at(&blob, 14);

        // Open + authenticate the MEK-sealed table under the case's MEK.
        let entries = open_sealed_record_table_v2(
            &blob,
            section_offset,
            section_len,
            &mek,
            &header.vault_id,
            header.schema_profile,
            wrk_frame_offset,
            blob.len(),
        )
        .unwrap_or_else(|_| panic!("{id}: sealed record table must open"));

        let records = c["expected"]["records"].as_array();
        assert_eq!(
            entries.len(),
            records.map_or(0, Vec::len),
            "{id}: record count"
        );
        if let Some(records) = records {
            for (entry, rec) in entries.iter().zip(records.iter()) {
                assert_eq!(
                    entry.record_id,
                    arr::<16>(rec["record_id"].as_str().unwrap()),
                    "{id}: record_id"
                );
                assert_eq!(
                    entry.record_kind,
                    u16_from_hex_tag(rec["record_kind"].as_str().unwrap()),
                    "{id}: record_kind"
                );
                assert_eq!(
                    entry.revision_id,
                    arr::<16>(rec["revision_id"].as_str().unwrap()),
                    "{id}: revision_id"
                );
                assert_eq!(
                    entry.frame_offset,
                    rec["frame_offset"].as_u64().unwrap(),
                    "{id}: frame_offset"
                );
                assert_eq!(
                    entry.frame_len,
                    rec["frame_len"].as_u64().unwrap() as u32,
                    "{id}: frame_len"
                );
            }
        }
    }
}

#[test]
fn unlock_and_list_accept_zero_entry_table_vault() {
    let (path, session) = unlocked_session("zero-entry-table");
    let summaries = list(&session).expect("zero-entry vault must list successfully");
    assert!(
        summaries.is_empty(),
        "zero-entry table must yield an empty list"
    );
    cleanup(&path, session);
}

#[test]
fn unlock_rejects_invalid_wrk_nonce_len_through_public_api() {
    let (path, session) = unlocked_session("invalid-wrk-nonce-len");
    drop(session.lock());

    let mut bytes = std::fs::read(&path).expect("read crafted vault bytes");
    let header_len = read_u32_at(&bytes, 10);
    let wrk_frame_offset = HEADER_MIN_LEN + header_len;
    let nonce_len_offset = wrk_frame_offset + 2 + 16 + 16 + 2;
    bytes[nonce_len_offset] = u8::MAX;
    std::fs::write(&path, &bytes).expect("rewrite crafted vault bytes");

    let err = match Vault::<Locked>::open(path.clone())
        .expect("open mutated vault")
        .unlock(UnlockParams {
            path: path.clone(),
            password: SecretBytes::new(TEST_VAULT_PASSWORD.to_vec()),
        }) {
        Ok(_) => panic!("invalid WRK nonce_len must fail through unlock()"),
        Err(err) => err,
    };
    assert!(
        matches!(err, CoreError::Format(_)),
        "invalid WRK nonce_len must reject with CoreError::Format"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn unlock_and_list_accept_bucket_boundary_multi_entry_vault() {
    let (path, session) = unlocked_session("bucket-boundary-multi-entry");
    for (label, secret) in [
        ("boundary-note-1", b"secret-1".as_slice()),
        ("boundary-note-2", b"secret-2".as_slice()),
        ("boundary-note-3", b"secret-3".as_slice()),
        ("boundary-note-4", b"secret-4".as_slice()),
    ] {
        add(&session, plain_note(label, secret)).expect("add test note");
    }

    let locked = session.lock();
    let reopened = Vault::<Locked>::open(path.clone())
        .expect("reopen boundary vault")
        .unlock(UnlockParams {
            path: path.clone(),
            password: SecretBytes::new(TEST_VAULT_PASSWORD.to_vec()),
        })
        .expect("unlock boundary vault");
    let summaries = list(&reopened).expect("multi-entry vault must list successfully");
    assert_eq!(
        summaries.len(),
        4,
        "bucket-boundary multi-entry vault must preserve all records"
    );
    drop(locked);
    cleanup(&path, reopened);
}

// ── vault_kdf_param_tlv_v1.json — KDF parameter TLV block (§4) ────────────────

#[test]
fn vault_kdf_param_tlv_v1_vectors() {
    let v = load("vault_kdf_param_tlv_v1.json");
    let c = find(&v, "kdf-param-tlv-argon2id-v1");
    let block = unhex(c["expected"]["kdf_profile_value_hex"].as_str().unwrap());

    // kdf_profile_value := profile_id:u16le || params_len:u32le || param TLVs
    let profile_id = u16::from_le_bytes(block[0..2].try_into().unwrap());
    assert_eq!(
        profile_id,
        c["inputs"]["profile_id"].as_u64().unwrap() as u16,
        "kdf: profile_id"
    );
    let params_len = u32::from_le_bytes(block[2..6].try_into().unwrap()) as usize;
    assert_eq!(
        params_len,
        c["expected"]["params_len"].as_u64().unwrap() as usize,
        "kdf: params_len"
    );
    let tlvs = &block[6..];
    assert_eq!(
        tlvs.len(),
        params_len,
        "kdf: param block length matches params_len"
    );

    // Walk KdfParamTlv := tag:u16le || len:u16le || value[len].
    let expected_tlvs = c["expected"]["parsed_tlvs"].as_array().unwrap();
    let mut cursor = 0usize;
    for exp in expected_tlvs {
        let tag = u16::from_le_bytes(tlvs[cursor..cursor + 2].try_into().unwrap());
        let len = u16::from_le_bytes(tlvs[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
        let value = &tlvs[cursor + 4..cursor + 4 + len];
        assert_eq!(
            tag,
            u16_from_hex_tag(exp["tag"].as_str().unwrap()),
            "kdf: tlv tag"
        );
        assert_eq!(len, exp["len"].as_u64().unwrap() as usize, "kdf: tlv len");
        assert_eq!(
            value,
            unhex(exp["value_hex"].as_str().unwrap()).as_slice(),
            "kdf: tlv value"
        );
        cursor += 4 + len;
    }
    assert_eq!(cursor, params_len, "kdf: consumed exactly params_len bytes");
    assert_eq!(expected_tlvs.len(), 5, "kdf: five Argon2id params");
}

#[test]
fn parse_kdf_profile_params_reads_argon2id_values_from_vector() {
    let v = load("vault_kdf_param_tlv_v1.json");
    let c = find(&v, "kdf-param-tlv-argon2id-v1");
    let params = parse_kdf_profile_params(&kdf_profile_value_from_vector())
        .expect("valid KDF parameter TLV must parse");

    assert_eq!(params.profile_id, KDF_ARGON2ID_V1, "profile id");
    assert_eq!(
        params.argon2.m_cost_kib,
        c["inputs"]["m_cost_kib"].as_u64().unwrap() as u32,
        "m_cost_kib"
    );
    assert_eq!(
        params.argon2.t_cost,
        c["inputs"]["t_cost"].as_u64().unwrap() as u32,
        "t_cost"
    );
    assert_eq!(
        params.argon2.p_lanes,
        c["inputs"]["p_lanes"].as_u64().unwrap() as u32,
        "p_lanes"
    );
    assert_eq!(
        params.argon2.output_len,
        c["inputs"]["output_len"].as_u64().unwrap() as usize,
        "output_len"
    );
    assert_eq!(params.argon2_version, ARGON2_VERSION_0X13, "argon2_version");
}

#[test]
fn parse_kdf_profile_params_rejects_wrong_argon2_version() {
    let mut block = kdf_profile_value_from_vector();
    let (offset, _) = find_kdf_param_tlv(&block, 0x0105).expect("argon2_version TLV");
    block[offset + 4..offset + 8].copy_from_slice(&0x12u32.to_le_bytes());

    assert!(matches!(
        parse_kdf_profile_params(&block),
        Err(CoreError::Format(_))
    ));
}

fn assert_missing_required_tag_rejected(tag: u16) {
    let mut block = kdf_profile_value_from_vector();
    remove_kdf_param_tlv(&mut block, tag);
    assert!(matches!(
        parse_kdf_profile_params(&block),
        Err(CoreError::Format(_))
    ));
}

#[test]
fn parse_kdf_profile_params_rejects_missing_m_cost_tag() {
    assert_missing_required_tag_rejected(0x0101);
}

#[test]
fn parse_kdf_profile_params_rejects_missing_t_cost_tag() {
    assert_missing_required_tag_rejected(0x0102);
}

#[test]
fn parse_kdf_profile_params_rejects_missing_p_lanes_tag() {
    assert_missing_required_tag_rejected(0x0103);
}

#[test]
fn parse_kdf_profile_params_rejects_missing_output_len_tag() {
    assert_missing_required_tag_rejected(0x0104);
}

#[test]
fn parse_kdf_profile_params_rejects_missing_argon2_version_tag() {
    assert_missing_required_tag_rejected(0x0105);
}

fn assert_duplicate_tag_rejected(tag: u16) {
    let mut block = kdf_profile_value_from_vector();
    duplicate_kdf_param_tlv(&mut block, tag);
    assert!(matches!(
        parse_kdf_profile_params(&block),
        Err(CoreError::Format(_))
    ));
}

#[test]
fn parse_kdf_profile_params_rejects_duplicate_m_cost_tag() {
    assert_duplicate_tag_rejected(0x0101);
}

#[test]
fn parse_kdf_profile_params_rejects_duplicate_t_cost_tag() {
    assert_duplicate_tag_rejected(0x0102);
}

#[test]
fn parse_kdf_profile_params_rejects_duplicate_p_lanes_tag() {
    assert_duplicate_tag_rejected(0x0103);
}

#[test]
fn parse_kdf_profile_params_rejects_duplicate_output_len_tag() {
    assert_duplicate_tag_rejected(0x0104);
}

#[test]
fn parse_kdf_profile_params_rejects_duplicate_argon2_version_tag() {
    assert_duplicate_tag_rejected(0x0105);
}

fn rewrite_tlv_len(block: &mut Vec<u8>, tag: u16, new_len: u16) {
    let (offset, total_len) = find_kdf_param_tlv(block, tag).expect("TLV tag present");
    let old_len = total_len - 4;
    block[offset + 2..offset + 4].copy_from_slice(&new_len.to_le_bytes());
    match usize::from(new_len).cmp(&old_len) {
        std::cmp::Ordering::Less => {
            let shrink = old_len - usize::from(new_len);
            let remove_start = offset + 4 + usize::from(new_len);
            block.drain(remove_start..remove_start + shrink);
            let next_params_len = kdf_params_len(block) - shrink;
            set_kdf_params_len(block, next_params_len as u32);
        }
        std::cmp::Ordering::Greater => {
            let grow = usize::from(new_len) - old_len;
            let insert_at = offset + 4 + old_len;
            block.splice(insert_at..insert_at, std::iter::repeat_n(0u8, grow));
            let next_params_len = kdf_params_len(block) + grow;
            set_kdf_params_len(block, next_params_len as u32);
        }
        std::cmp::Ordering::Equal => {}
    }
}

fn assert_wrong_tlv_width_rejected(tag: u16, wrong_len: u16) {
    let mut block = kdf_profile_value_from_vector();
    rewrite_tlv_len(&mut block, tag, wrong_len);
    assert!(matches!(
        parse_kdf_profile_params(&block),
        Err(CoreError::Format(_))
    ));
}

#[test]
fn parse_kdf_profile_params_rejects_wrong_encoded_type_for_m_cost_tag() {
    assert_wrong_tlv_width_rejected(0x0101, 2);
}

#[test]
fn parse_kdf_profile_params_rejects_wrong_encoded_type_for_t_cost_tag() {
    assert_wrong_tlv_width_rejected(0x0102, 2);
}

#[test]
fn parse_kdf_profile_params_rejects_wrong_encoded_type_for_p_lanes_tag() {
    assert_wrong_tlv_width_rejected(0x0103, 2);
}

#[test]
fn parse_kdf_profile_params_rejects_wrong_encoded_type_for_output_len_tag() {
    assert_wrong_tlv_width_rejected(0x0104, 4);
}

#[test]
fn parse_kdf_profile_params_rejects_wrong_encoded_type_for_argon2_version_tag() {
    assert_wrong_tlv_width_rejected(0x0105, 2);
}

#[test]
fn parse_kdf_profile_params_rejects_wrong_value_length() {
    let mut block = kdf_profile_value_from_vector();
    let (offset, _) = find_kdf_param_tlv(&block, 0x0104).expect("output_len TLV");
    block[offset + 2..offset + 4].copy_from_slice(&4u16.to_le_bytes());
    let next_params_len = kdf_params_len(&block) + 2;
    set_kdf_params_len(&mut block, next_params_len as u32);
    block.splice(offset + 6..offset + 6, [0u8, 0u8]);

    assert!(matches!(
        parse_kdf_profile_params(&block),
        Err(CoreError::Format(_))
    ));
}

#[test]
fn parse_kdf_profile_params_rejects_params_len_shorter_than_tlvs() {
    let mut block = kdf_profile_value_from_vector();
    let next_params_len = kdf_params_len(&block) - 1;
    set_kdf_params_len(&mut block, next_params_len as u32);

    assert!(matches!(
        parse_kdf_profile_params(&block),
        Err(CoreError::Format(_))
    ));
}

#[test]
fn parse_kdf_profile_params_rejects_params_len_longer_than_body() {
    let mut block = kdf_profile_value_from_vector();
    let next_params_len = kdf_params_len(&block) + 1;
    set_kdf_params_len(&mut block, next_params_len as u32);

    assert!(matches!(
        parse_kdf_profile_params(&block),
        Err(CoreError::Format(_))
    ));
}

#[test]
fn parse_kdf_profile_params_rejects_trailing_garbage_after_declared_params() {
    let mut block = kdf_profile_value_from_vector();
    block.extend_from_slice(&[0xaa, 0xbb]);

    assert!(matches!(
        parse_kdf_profile_params(&block),
        Err(CoreError::Format(_))
    ));
}

#[test]
fn parse_kdf_profile_params_rejects_unknown_profile_id() {
    let mut block = kdf_profile_value_from_vector();
    block[0..2].copy_from_slice(&0x0002u16.to_le_bytes());

    assert!(matches!(
        parse_kdf_profile_params(&block),
        Err(CoreError::Format(_))
    ));
}

// F-61/F-66: below-minimum profile params must be rejected so attacker-controlled
// vault/bundle headers cannot collapse brute-force cost below the registered floor.
// Tags: 0x0101=m_cost_kib, 0x0102=t_cost, 0x0103=p_lanes (each u32le at TLV offset +4).

#[test]
fn parse_kdf_profile_params_rejects_m_cost_below_minimum() {
    let mut block = kdf_profile_value_from_vector();
    let (offset, _) = find_kdf_param_tlv(&block, 0x0101).expect("m_cost_kib TLV");
    block[offset + 4..offset + 8].copy_from_slice(&8u32.to_le_bytes());
    assert!(matches!(
        parse_kdf_profile_params(&block),
        Err(CoreError::Format(_))
    ));
}

#[test]
fn parse_kdf_profile_params_rejects_t_cost_below_minimum() {
    let mut block = kdf_profile_value_from_vector();
    let (offset, _) = find_kdf_param_tlv(&block, 0x0102).expect("t_cost TLV");
    block[offset + 4..offset + 8].copy_from_slice(&2u32.to_le_bytes());
    assert!(matches!(
        parse_kdf_profile_params(&block),
        Err(CoreError::Format(_))
    ));
}

#[test]
fn parse_kdf_profile_params_rejects_p_lanes_below_minimum() {
    let mut block = kdf_profile_value_from_vector();
    let (offset, _) = find_kdf_param_tlv(&block, 0x0103).expect("p_lanes TLV");
    block[offset + 4..offset + 8].copy_from_slice(&3u32.to_le_bytes());
    assert!(matches!(
        parse_kdf_profile_params(&block),
        Err(CoreError::Format(_))
    ));
}

#[test]
#[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
fn header_sourced_kdf_params_reproduce_existing_muk_vector() {
    let params = parse_kdf_profile_params(&kdf_profile_value_from_vector())
        .expect("valid KDF parameter TLV must parse");
    let v = load("vault_kdf_v1.json");
    let c = find(&v, "muk-derivation");
    let password = c["inputs"]["password"].as_str().unwrap().as_bytes();
    let vault_id = arr::<16>(c["inputs"]["vault_id"].as_str().unwrap());
    let expected_muk = MasterUnlockKey::from_bytes(arr::<32>(
        c["expected"]["master_unlock_key"].as_str().unwrap(),
    ));

    let muk = derive_master_unlock_key_with_header_params(password, &vault_id, &params)
        .expect("header-sourced params must reproduce the existing MUK vector");

    assert!(bool::from(muk.ct_eq(&expected_muk)), "MUK vector");
}

#[test]
fn vault_kdf_v1_all_seven_subkeys_match_vectors() {
    let c = subkey_derivation_case();
    let expected = &c["expected"];
    let keys = derive_vector_unlocked_keys();
    let item_wrap_key = Key::<32>::from_bytes(arr::<32>(
        expected["item_key_wrapping_key"].as_str().unwrap(),
    ));
    let metadata_key = Key::<32>::from_bytes(arr::<32>(
        expected["metadata_encryption_key"].as_str().unwrap(),
    ));
    let audit_key = Key::<32>::from_bytes(arr::<32>(
        expected["local_audit_event_key"].as_str().unwrap(),
    ));
    let sync_envelope_key =
        Key::<32>::from_bytes(arr::<32>(expected["sync_envelope_key"].as_str().unwrap()));
    let device_enrollment_key = Key::<32>::from_bytes(arr::<32>(
        expected["device_enrollment_key"].as_str().unwrap(),
    ));
    let recovery_wrapping_key = Key::<32>::from_bytes(arr::<32>(
        expected["recovery_wrapping_key"].as_str().unwrap(),
    ));
    let export_key =
        Key::<32>::from_bytes(arr::<32>(expected["export_bundle_key"].as_str().unwrap()));

    assert!(
        bool::from(keys.item_wrap_key.ct_eq(&item_wrap_key)),
        "item key wrapping key"
    );
    assert!(
        bool::from(keys.metadata_key.ct_eq(&metadata_key)),
        "metadata encryption key"
    );
    assert!(
        bool::from(keys.audit_key.ct_eq(&audit_key)),
        "local audit event key"
    );
    assert!(
        bool::from(keys.sync_envelope_key.ct_eq(&sync_envelope_key)),
        "sync envelope key"
    );
    assert!(
        bool::from(keys.device_enrollment_key.ct_eq(&device_enrollment_key)),
        "device enrollment key"
    );
    assert!(
        bool::from(keys.recovery_wrapping_key.ct_eq(&recovery_wrapping_key)),
        "recovery wrapping key"
    );
    assert!(
        bool::from(keys.export_key.ct_eq(&export_key)),
        "export bundle key"
    );
}

#[test]
fn vault_kdf_v1_all_seven_subkeys_are_pairwise_distinct() {
    let keys = derive_vector_unlocked_keys();
    let subkeys = vector_subkeys(&keys);

    for (left_index, left) in subkeys.iter().enumerate() {
        for right in subkeys.iter().skip(left_index + 1) {
            assert!(
                !bool::from(left.ct_eq(right)),
                "HKDF registry subkeys must be pairwise domain-separated"
            );
        }
    }
}

#[test]
fn unlocked_keys_exposes_all_seven_registry_subkeys() {
    fn require_all_fields(keys: &UnlockedKeys) -> [&[u8]; 7] {
        [
            keys.item_wrap_key.as_slice(),
            keys.metadata_key.as_slice(),
            keys.audit_key.as_slice(),
            keys.sync_envelope_key.as_slice(),
            keys.device_enrollment_key.as_slice(),
            keys.recovery_wrapping_key.as_slice(),
            keys.export_key.as_slice(),
        ]
    }

    let keys = derive_vector_unlocked_keys();
    assert_eq!(require_all_fields(&keys).len(), 7);
}

// ── vault_format_negative_v1.json — V2 §10 reject rules (fail closed) ─────────

#[test]
fn vault_format_negative_v1_vectors() {
    let v = load("vault_format_negative_v1.json");

    // Every V2 negative table fixture was sealed under the shared fixed test MEK
    // carried by the positive struct vector; read it rather than hardcoding.
    let sv = load("vault_format_struct_v1.json");
    let mek = AeadKey::from_bytes(arr::<32>(
        find(&sv, "v2-empty-table-fixed-wrk")["inputs"]["metadata_encryption_key"]
            .as_str()
            .unwrap(),
    ));

    for c in v["cases"].as_array().expect("cases") {
        let id = c["id"].as_str().expect("id");
        let reason = c["expected"]["reason"].as_str().expect("reason");
        assert_eq!(
            c["expected"]["result"].as_str(),
            Some("Err"),
            "case {id}: must be a reject case"
        );
        let blob = unhex(c["inputs"]["input_hex"].as_str().unwrap());

        if reason == "schema_profile_v1" {
            // V2 readers never best-effort parse the pre-release V1 schema; the
            // header parser rejects it outright.
            assert!(
                parse_header(&blob).is_err(),
                "case {id}: parse_header must reject schema_profile V1"
            );
            continue;
        }

        // Every other negative is a valid V2 header whose MEK-sealed table must
        // be rejected: bad sealed_table_len, non-bucket length, non-zero padding,
        // a WrappedRootKey entry, or AEAD authentication failure (§10). None may
        // yield partial table output.
        let header = parse_header(&blob).unwrap_or_else(|_| panic!("case {id}: header parses"));
        let header_len = read_u32_at(&blob, 10);
        let wrk_frame_offset = HEADER_MIN_LEN + header_len;
        let section_offset = wrk_frame_offset + record_frame_len_at(&blob, wrk_frame_offset);
        let section_len = read_u32_at(&blob, 14);
        let opened = open_sealed_record_table_v2(
            &blob,
            section_offset,
            section_len,
            &mek,
            &header.vault_id,
            header.schema_profile,
            wrk_frame_offset,
            blob.len(),
        );
        assert!(
            opened.is_err(),
            "case {id}: sealed record table must reject ({reason})"
        );
    }
}

// ── export_import_v1.json — encrypted .msexp export/import KATs ──────────────

#[test]
#[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
fn export_import_v1_roundtrip_and_kat_bundle_vectors() {
    let vectors = load("export_import_v1.json");
    let case = find(&vectors, "export-import-roundtrip-v1");
    let export_passphrase = case["inputs"]["export_passphrase_utf8"]
        .as_str()
        .expect("export passphrase")
        .as_bytes();
    let expected_items = case["expected"]["expected_items"]
        .as_array()
        .expect("expected items");
    let bundle = unhex(case["expected"]["bundle_hex"].as_str().expect("bundle hex"));

    let (source_path, source) = unlocked_session("export-import-roundtrip-source");
    let (target_path, target) = unlocked_session("export-import-roundtrip-target");
    let (kat_path, kat_target) = unlocked_session("export-import-roundtrip-kat");

    for item in case["inputs"]["items"].as_array().expect("input items") {
        add(&source, plain_item_from_vector(item)).expect("vector item add must succeed");
    }

    let exported = export(&source, export_passphrase).expect("production export must succeed");
    let imported_ids =
        import(&target, &exported, export_passphrase).expect("production import must succeed");
    assert_eq!(
        imported_ids.len(),
        expected_items.len(),
        "round-trip import count must match vector"
    );
    assert_imported_items(&target, expected_items);

    let kat_imported_ids =
        import(&kat_target, &bundle, export_passphrase).expect("KAT bundle import must succeed");
    assert_eq!(
        kat_imported_ids.len(),
        expected_items.len(),
        "KAT bundle import count must match vector"
    );
    assert_imported_items(&kat_target, expected_items);

    cleanup(&source_path, source);
    cleanup(&target_path, target);
    cleanup(&kat_path, kat_target);
}

#[test]
#[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
fn export_import_v1_ciphertext_corruption_rejects_with_auth() {
    let vectors = load("export_import_v1.json");
    let case = find(&vectors, "export-import-ciphertext-corruption-v1");
    let export_passphrase = case["inputs"]["export_passphrase_utf8"]
        .as_str()
        .expect("export passphrase")
        .as_bytes();
    let bundle = unhex(case["inputs"]["bundle_hex"].as_str().expect("bundle hex"));
    let (path, session) = unlocked_session("export-import-corruption");

    let err =
        import(&session, &bundle, export_passphrase).expect_err("tampered bundle must reject");
    assert!(
        matches!(err, CoreError::Auth),
        "tampered bundle must reject with CoreError::Auth"
    );

    cleanup(&path, session);
}

#[test]
#[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
fn export_import_v1_wrong_decryption_key_rejects_with_auth() {
    let vectors = load("export_import_v1.json");
    let case = find(&vectors, "export-import-wrong-decryption-key-v1");
    let wrong_passphrase = case["inputs"]["wrong_passphrase_utf8"]
        .as_str()
        .expect("wrong passphrase")
        .as_bytes();
    let bundle = unhex(case["inputs"]["bundle_hex"].as_str().expect("bundle hex"));
    let (path, session) = unlocked_session("export-import-wrong-key");

    let err =
        import(&session, &bundle, wrong_passphrase).expect_err("wrong decryption key must reject");
    assert!(
        matches!(err, CoreError::Auth),
        "wrong decryption key must reject with CoreError::Auth"
    );

    cleanup(&path, session);
}
