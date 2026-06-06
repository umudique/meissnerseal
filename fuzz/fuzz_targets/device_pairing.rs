#![no_main]
use libfuzzer_sys::fuzz_target;

// PENDING: the device_pairing parser is not implemented until MVP-3 (device
// enrollment). This target is intentionally inert until that parser exists; it
// is not counted toward the "fuzz-tested parsers" claim today.
fuzz_target!(|_data: &[u8]| {});
