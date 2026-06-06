#![no_main]
use libfuzzer_sys::fuzz_target;

// PENDING: the transfer_envelope parser is not implemented until MVP-2 (PQC
// hybrid transfer). This target is intentionally inert until that parser
// exists; it is not counted toward the "fuzz-tested parsers" claim today.
fuzz_target!(|_data: &[u8]| {});
