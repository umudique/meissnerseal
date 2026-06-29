// SPDX-License-Identifier: Apache-2.0
//! Cryptographic hash helpers.

use sha2::{Digest, Sha256};

/// Compute SHA-256 over caller-provided bytes.
///
/// # Contract
///
/// ## Preconditions
/// - `input` is the exact byte string selected by the caller's protocol
///   specification.
///
/// ## Postconditions
/// - Returns the 32-byte SHA-256 digest of `input`.
///
/// ## Invariants
/// - Uses the RustCrypto `sha2::Sha256` implementation through the `Digest`
///   trait.
/// - Does not log, print, or write input bytes or digest bytes.
#[must_use]
pub fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_bytes_empty_matches_known_hash() {
        assert_eq!(
            sha256_bytes(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }
}
