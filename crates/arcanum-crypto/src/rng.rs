//! OS CSPRNG helpers.

use rand::{rngs::OsRng, RngCore};

/// Return `len` bytes from the operating system CSPRNG.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Return a 32-byte key from the operating system CSPRNG.
pub fn random_key() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Return a 24-byte XChaCha20 nonce from the operating system CSPRNG.
pub fn random_nonce_xchacha20() -> [u8; 24] {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
