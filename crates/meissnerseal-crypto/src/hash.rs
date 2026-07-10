// SPDX-License-Identifier: Apache-2.0
//! Cryptographic hash helpers.

use blake2::{Blake2b, Digest};
use sha2::Sha256;

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

/// Compute BLAKE2b-256 over caller-provided bytes.
///
/// # Contract
///
/// ## Preconditions
/// - `input` is the exact byte string selected by the caller's protocol
///   specification.
///
/// ## Postconditions
/// - Returns the 32-byte BLAKE2b-256 digest of `input`.
///
/// ## Invariants
/// - Uses the RustCrypto `blake2::Blake2b` implementation through the `Digest`
///   trait with a 32-byte output length.
/// - Does not log, print, or write input bytes or digest bytes.
#[must_use]
pub fn blake2b_256_bytes(input: &[u8]) -> [u8; 32] {
    Blake2b::<blake2::digest::consts::U32>::digest(input).into()
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

    #[test]
    fn sha256_bytes_abc_matches_fips_180_4_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn blake2b_256_bytes_matches_known_vectors() {
        assert_eq!(
            blake2b_256_bytes(b"abc"),
            [
                0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f, 0xee, 0x98,
                0x57, 0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0,
                0x68, 0xd5, 0x23, 0x19,
            ]
        );
        assert_eq!(
            blake2b_256_bytes(b""),
            [
                0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99,
                0xda, 0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd,
                0xf1, 0x2f, 0xe3, 0xa8,
            ]
        );
    }
}
