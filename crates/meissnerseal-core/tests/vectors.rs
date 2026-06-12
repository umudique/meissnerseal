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
use meissnerseal_crypto::types::{AeadKey, HkdfPrk, Key};
use serde_json::Value;
use std::path::PathBuf;

// ── helpers ──────────────────────────────────────────────────────────────────

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors")
}

fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("valid JSON vector file")
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

    assert!(parse_kdf_profile_params(&block).is_err());
}

#[test]
fn parse_kdf_profile_params_rejects_missing_required_tag() {
    let mut block = kdf_profile_value_from_vector();
    remove_kdf_param_tlv(&mut block, 0x0102);

    assert!(parse_kdf_profile_params(&block).is_err());
}

#[test]
fn parse_kdf_profile_params_rejects_duplicate_tag() {
    let mut block = kdf_profile_value_from_vector();
    duplicate_kdf_param_tlv(&mut block, 0x0101);

    assert!(parse_kdf_profile_params(&block).is_err());
}

#[test]
fn parse_kdf_profile_params_rejects_wrong_value_length() {
    let mut block = kdf_profile_value_from_vector();
    let (offset, _) = find_kdf_param_tlv(&block, 0x0104).expect("output_len TLV");
    block[offset + 2..offset + 4].copy_from_slice(&4u16.to_le_bytes());
    let next_params_len = kdf_params_len(&block) + 2;
    set_kdf_params_len(&mut block, next_params_len as u32);
    block.splice(offset + 6..offset + 6, [0u8, 0u8]);

    assert!(parse_kdf_profile_params(&block).is_err());
}

#[test]
fn parse_kdf_profile_params_rejects_params_len_shorter_than_tlvs() {
    let mut block = kdf_profile_value_from_vector();
    let next_params_len = kdf_params_len(&block) - 1;
    set_kdf_params_len(&mut block, next_params_len as u32);

    assert!(parse_kdf_profile_params(&block).is_err());
}

#[test]
fn parse_kdf_profile_params_rejects_trailing_garbage_after_declared_params() {
    let mut block = kdf_profile_value_from_vector();
    block.extend_from_slice(&[0xaa, 0xbb]);

    assert!(parse_kdf_profile_params(&block).is_err());
}

#[test]
fn parse_kdf_profile_params_rejects_unknown_profile_id() {
    let mut block = kdf_profile_value_from_vector();
    block[0..2].copy_from_slice(&0x0002u16.to_le_bytes());

    assert!(parse_kdf_profile_params(&block).is_err());
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
    let expected_muk = unhex(c["expected"]["master_unlock_key"].as_str().unwrap());

    let muk = derive_master_unlock_key_with_header_params(password, &vault_id, &params)
        .expect("header-sourced params must reproduce the existing MUK vector");

    assert_eq!(muk.as_slice(), expected_muk.as_slice(), "MUK vector");
}

#[test]
fn vault_kdf_v1_all_seven_subkeys_match_vectors() {
    let c = subkey_derivation_case();
    let expected = &c["expected"];
    let keys = derive_vector_unlocked_keys();

    assert_eq!(
        keys.item_wrap_key.as_slice(),
        unhex(expected["item_key_wrapping_key"].as_str().unwrap()).as_slice(),
        "item key wrapping key"
    );
    assert_eq!(
        keys.metadata_key.as_slice(),
        unhex(expected["metadata_encryption_key"].as_str().unwrap()).as_slice(),
        "metadata encryption key"
    );
    assert_eq!(
        keys.audit_key.as_slice(),
        unhex(expected["local_audit_event_key"].as_str().unwrap()).as_slice(),
        "local audit event key"
    );
    assert_eq!(
        keys.sync_envelope_key.as_slice(),
        unhex(expected["sync_envelope_key"].as_str().unwrap()).as_slice(),
        "sync envelope key"
    );
    assert_eq!(
        keys.device_enrollment_key.as_slice(),
        unhex(expected["device_enrollment_key"].as_str().unwrap()).as_slice(),
        "device enrollment key"
    );
    assert_eq!(
        keys.recovery_wrapping_key.as_slice(),
        unhex(expected["recovery_wrapping_key"].as_str().unwrap()).as_slice(),
        "recovery wrapping key"
    );
    assert_eq!(
        keys.export_key.as_slice(),
        unhex(expected["export_bundle_key"].as_str().unwrap()).as_slice(),
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
