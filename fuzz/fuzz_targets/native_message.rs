#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    // TODO: invoke native_message parser — must fail closed on all malformed input
});
