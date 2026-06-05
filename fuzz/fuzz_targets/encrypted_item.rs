#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    // TODO: invoke encrypted_item parser — must fail closed on all malformed input
});
