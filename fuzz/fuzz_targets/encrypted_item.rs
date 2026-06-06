#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzzes the record-frame ("encrypted item") parser. The declared frame_len is
// taken from the first 4 bytes so the fuzzer can exercise length/bounds
// mismatch paths against the frame body. Must fail closed on all malformed
// input — never panic, never partial output.
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let frame_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let _ = arcanum_core::vault::format::parse_record_frame(&data[4..], frame_len);
});
