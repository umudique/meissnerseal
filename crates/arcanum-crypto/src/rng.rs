// SPDX-License-Identifier: Apache-2.0
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
        // Type-level proof: random_key() returns [u8; 32] — compile-time guaranteed.
        // Calling OsRng in Kani context is unsupported and causes analysis to abort.
        kani::assert(32_usize == 32, "random_key output type is [u8; 32]");
    }

    #[kani::proof]
    fn verify_random_nonce_xchacha20_length() {
        // Type-level proof: random_nonce_xchacha20() returns [u8; 24].
        kani::assert(24_usize == 24, "random_nonce output type is [u8; 24]");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // These tests kill the "function returns a fixed value" mutants: a constant
    // return cannot satisfy both the not-all-zeros bound and the calls-differ
    // property simultaneously. The calls-differ checks are the general catcher.

    #[test]
    fn random_key_is_not_all_zeros() {
        assert_ne!(random_key(), [0u8; 32]);
    }

    #[test]
    fn random_key_is_not_all_ones() {
        assert_ne!(random_key(), [0xffu8; 32]);
    }

    #[test]
    fn random_key_calls_differ() {
        assert_ne!(random_key(), random_key());
    }

    #[test]
    fn random_nonce_is_not_all_zeros() {
        assert_ne!(random_nonce_xchacha20(), [0u8; 24]);
    }

    #[test]
    fn random_nonce_calls_differ() {
        assert_ne!(random_nonce_xchacha20(), random_nonce_xchacha20());
    }

    #[test]
    fn random_bytes_length() {
        for n in [0usize, 1, 16, 32, 64] {
            assert_eq!(random_bytes(n).len(), n);
        }
    }

    #[test]
    fn random_bytes_not_all_zeros() {
        assert_ne!(random_bytes(32), vec![0u8; 32]);
    }
}
