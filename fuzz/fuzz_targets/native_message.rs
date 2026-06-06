#![no_main]
use libfuzzer_sys::fuzz_target;

// PENDING: the native_message parser (browser native-messaging host) is not
// implemented until MVP-3. This target is intentionally inert until that parser
// exists; it is not counted toward the "fuzz-tested parsers" claim today.
fuzz_target!(|_data: &[u8]| {});
