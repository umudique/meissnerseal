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

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn verify_random_key_length() {
        let key = random_key();
        kani::assert(key.len() == 32, "random_key must produce 32 bytes");
    }

    #[kani::proof]
    fn verify_random_nonce_xchacha20_length() {
        let nonce = random_nonce_xchacha20();
        kani::assert(
            nonce.len() == 24,
            "random_nonce_xchacha20 must produce 24 bytes",
        );
    }
}
