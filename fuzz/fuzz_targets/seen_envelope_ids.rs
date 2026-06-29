#![no_main]
use libfuzzer_sys::fuzz_target;
use meissnerseal_core::transfer::{SeenEnvelopeIds, TransferError};

const MAX_DIRECT_COUNT: u32 = 1024;

fuzz_target!(|data: &[u8]| {
    // Raw parser call for ordinary fuzz input. Very large declared counts are
    // normalized before direct parsing to avoid allocator aborts masking parser
    // behavior in the smoke target.
    if declared_count(data).is_none_or(|count| count <= MAX_DIRECT_COUNT) {
        exercise(data);
    } else {
        let mut bounded = data.to_vec();
        bounded[..4].copy_from_slice(&MAX_DIRECT_COUNT.to_le_bytes());
        exercise(&bounded);
    }

    // Truncated before count:u32le.
    let count_cut = data.len().min(3);
    exercise(&data[..count_cut]);

    // Count declares more entries than bytes remain.
    let mut overdeclared = Vec::new();
    overdeclared.extend_from_slice(&2u32.to_le_bytes());
    append_seeded(&mut overdeclared, data, 24, 0);
    exercise(&overdeclared);

    // Truncated mid-entry, both within the 16-byte ID and the 8-byte expiry.
    let mut id_cut = Vec::new();
    id_cut.extend_from_slice(&1u32.to_le_bytes());
    append_seeded(&mut id_cut, data, 15, 0);
    exercise(&id_cut);

    let mut expiry_cut = Vec::new();
    expiry_cut.extend_from_slice(&1u32.to_le_bytes());
    append_seeded(&mut expiry_cut, data, 16, 0);
    append_seeded(&mut expiry_cut, data, 7, 16);
    exercise(&expiry_cut);

    // Trailing garbage after a complete zero-entry and one-entry store.
    let mut zero_trailing = Vec::new();
    zero_trailing.extend_from_slice(&0u32.to_le_bytes());
    zero_trailing.push(0xAA);
    exercise(&zero_trailing);

    let mut one_trailing = Vec::new();
    one_trailing.extend_from_slice(&1u32.to_le_bytes());
    append_seeded(&mut one_trailing, data, 24, 0);
    one_trailing.push(0xBB);
    exercise(&one_trailing);
});

fn exercise(bytes: &[u8]) {
    match SeenEnvelopeIds::from_bytes(bytes) {
        Ok(_) => {}
        Err(TransferError::MalformedReplayStore) => {}
        Err(other) => panic!("unexpected seen envelope IDs parser error: {other:?}"),
    }
}

fn declared_count(bytes: &[u8]) -> Option<u32> {
    let count = bytes.get(..4)?;
    Some(u32::from_le_bytes([count[0], count[1], count[2], count[3]]))
}

fn append_seeded(out: &mut Vec<u8>, seed: &[u8], len: usize, offset: usize) {
    for index in 0..len {
        out.push(seed.get(offset + index).copied().unwrap_or(0));
    }
}
