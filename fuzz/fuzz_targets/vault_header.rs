#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzzes the vault header and record-table parsers. Both must fail closed —
// return Err on any malformed input, never panic and never produce partial
// output (AGENTS.md §4, vault_format_v1.md fail-closed parsing).
fuzz_target!(|data: &[u8]| {
    let _ = arcanum_core::vault::format::parse_header(data);

    // Drive the record-table parser with a fuzzer-chosen offset/len so its
    // bounds and overflow checks face adversarial framing.
    if data.len() >= 4 {
        let offset = usize::from(u16::from_le_bytes([data[0], data[1]]));
        let len = usize::from(u16::from_le_bytes([data[2], data[3]]));
        let _ = arcanum_core::vault::format::parse_record_table(data, offset, len);
    }
});
