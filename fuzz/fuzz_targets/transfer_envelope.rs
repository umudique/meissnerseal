#![no_main]
use libfuzzer_sys::fuzz_target;
use meissnerseal_core::transfer::{envelope::envelope_from_bytes, TransferError};

const MAGIC: &[u8; 6] = b"MSENV\x01";
const MIN_PREFIX_AFTER_MAGIC: usize = 2 + 2 + 16 + 16 + 1;
// Byte offset of the recipient_tag field: magic(6) + version(2) + profile_id(2) + envelope_id(16) + sender_device_id(16)
const RECIPIENT_TAG_OFFSET: usize = 6 + 2 + 2 + 16 + 16;

fuzz_target!(|data: &[u8]| {
    exercise(data);

    // Wrong or missing magic bytes.
    if !data.is_empty() {
        let mut wrong_magic = data.to_vec();
        wrong_magic[0] ^= 0xFF;
        exercise(&wrong_magic);
    }

    // Unknown version / transfer_profile_id with enough prefix to reach those fields.
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&2u16.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    header.resize(MAGIC.len() + MIN_PREFIX_AFTER_MAGIC, 0);
    exercise(&header);

    let mut unknown_profile = header.clone();
    unknown_profile[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&1u16.to_le_bytes());
    unknown_profile[MAGIC.len() + 2..MAGIC.len() + 4].copy_from_slice(&0xFFFFu16.to_le_bytes());
    exercise(&unknown_profile);

    // Bad recipient tag and expiry tag critical fields.
    let mut bad_recipient_tag = minimal_envelope_like(data, 0, 0, 0);
    bad_recipient_tag[RECIPIENT_TAG_OFFSET] = 0xFF;
    exercise(&bad_recipient_tag);

    let mut bad_expiry_tag = minimal_envelope_like(data, 0, 0, 0);
    let expiry_tag_offset = 6 + 2 + 2 + 16 + 16 + 1 + 32 + 4 + 1088 + 32 + 24;
    bad_expiry_tag[expiry_tag_offset] = 0xFF;
    exercise(&bad_expiry_tag);

    // expires_at absent, present-zero, and present-nonzero tag distinction.
    exercise(&minimal_envelope_like(data, 0, 0, 0));
    exercise(&minimal_envelope_like(data, 0, 1, 0));
    exercise(&minimal_envelope_like(data, 0, 1, 1));

    // Length mismatch / corrupted ciphertext region and trailing garbage.
    let mut mismatched_pqc_len = minimal_envelope_like(data, 0, 0, 0);
    let pqc_len_offset = 6 + 2 + 2 + 16 + 16 + 1 + 32;
    mismatched_pqc_len[pqc_len_offset..pqc_len_offset + 4].copy_from_slice(&1089u32.to_le_bytes());
    exercise(&mismatched_pqc_len);

    let mut trailing_garbage = minimal_envelope_like(data, 0, 0, 0);
    trailing_garbage.push(0xAA);
    exercise(&trailing_garbage);

    // Truncated input at arbitrary field boundaries.
    let complete = minimal_envelope_like(data, 0, 1, 0);
    if !complete.is_empty() {
        let cut = data.first().copied().unwrap_or(0) as usize % complete.len();
        exercise(&complete[..cut]);
    }
});

fn exercise(bytes: &[u8]) {
    match envelope_from_bytes(bytes) {
        Ok(_) => {}
        Err(TransferError::UnknownProfile) => {}
        Err(other) => panic!("unexpected transfer envelope parser error: {other:?}"),
    }
}

fn minimal_envelope_like(seed: &[u8], recipient_tag: u8, expiry_tag: u8, expiry: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    append_seeded(&mut out, seed, 16, 0);
    append_seeded(&mut out, seed, 16, 16);
    out.push(recipient_tag);
    if recipient_tag == 1 {
        append_seeded(&mut out, seed, 16, 32);
    }
    append_seeded(&mut out, seed, 32, 48);
    out.extend_from_slice(&1088u32.to_le_bytes());
    append_seeded(&mut out, seed, 1088, 80);
    append_seeded(&mut out, seed, 32, 1168);
    append_seeded(&mut out, seed, 24, 1200);
    out.push(expiry_tag);
    if expiry_tag == 1 {
        out.extend_from_slice(&expiry.to_le_bytes());
    }
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

fn append_seeded(out: &mut Vec<u8>, seed: &[u8], len: usize, offset: usize) {
    for index in 0..len {
        out.push(seed.get(offset + index).copied().unwrap_or(0));
    }
}
