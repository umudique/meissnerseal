#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    // TODO: invoke sync_envelope parser — must fail closed on all malformed input
});
