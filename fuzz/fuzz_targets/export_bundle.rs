#![no_main]
use libfuzzer_sys::fuzz_target;
use meissnerseal_core::{
    error::CoreError,
    export::UntrustedExportBundle,
};

const PASSPHRASE: &[u8] = b"fuzz-export-passphrase-never-real";

fuzz_target!(|data: &[u8]| {
    exercise(data);

    if !data.is_empty() {
        let mut wrong_magic = data.to_vec();
        wrong_magic[0] ^= 0xFF;
        exercise(&wrong_magic);
    }

    let cut = data.len().min(31);
    exercise(&data[..cut]);

    let mut trailing = data.to_vec();
    trailing.push(0xAA);
    exercise(&trailing);
});

fn exercise(bytes: &[u8]) {
    match UntrustedExportBundle::authenticate(bytes, PASSPHRASE) {
        Ok(_) => {}
        Err(CoreError::Format(_)) | Err(CoreError::Auth) | Err(CoreError::Crypto) => {}
        Err(other) => panic!("unexpected export parser/auth error: {other:?}"),
    }
}
