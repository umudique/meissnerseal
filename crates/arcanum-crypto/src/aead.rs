//! AEAD_XCHACHA20_POLY1305_V1 contracts.
//!
use crate::types::{AeadKey, XChaCha20Nonce};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// XChaCha20-Poly1305 authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// AEAD ciphertext bytes with the authentication tag appended.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ciphertext(Vec<u8>);

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

// Allows arcanum-core to wrap ciphertext bytes loaded from the vault file
// so they can be passed to `decrypt()`. This is the only public constructor.
impl From<Vec<u8>> for Ciphertext {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ciphertext([REDACTED])")
    }
}

/// Decrypted plaintext bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Plaintext(Vec<u8>);

impl AsRef<[u8]> for Plaintext {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl core::fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Plaintext([REDACTED])")
    }
}

/// AEAD module error.
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    /// Encryption failed without producing ciphertext.
    #[error("AEAD encryption failed")]
    Encrypt,

    /// Authentication or input validation failed without producing plaintext.
    #[error("AEAD decryption failed")]
    Decrypt,

    /// Nonce generation failed.
    #[error("AEAD nonce generation failed")]
    Nonce,
}

/// AEAD module result type.
pub type Result<T> = core::result::Result<T, AeadError>;

/// Encrypt plaintext using AEAD_XCHACHA20_POLY1305_V1.
///
/// # Contract
/// ## Preconditions
/// - `key` is a 32-byte `AeadKey` derived by this crate's key derivation APIs.
/// - `plaintext` is caller-owned secret input and is never logged, printed, or
///   written to any output except the returned authenticated ciphertext.
/// - `aad` is the caller-supplied canonical 74-byte AAD construction.
/// ## Postconditions
/// - On success, returns `(Ciphertext, XChaCha20Nonce)` containing
///   `ciphertext_bytes || tag` and the generated nonce to store with the record.
/// - On success, returned ciphertext length is `plaintext.len() + TAG_LEN`.
/// - On failure, returns `Err` and exposes no partial ciphertext.
/// ## Invariants
/// - Uses no custom cryptographic primitive; implementation must use the
///   `chacha20poly1305` crate.
/// - Generates the nonce internally using the OS CSPRNG; callers cannot supply
///   production encryption nonces.
/// - Authentication tag length is 16 bytes and is appended to ciphertext.
/// - Secret values are not logged, printed, written, or compared with `==`.
pub fn encrypt(
    key: &AeadKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Ciphertext, XChaCha20Nonce)> {
    let nonce = generate_nonce();
    let ciphertext = encrypt_with_generated_nonce(key, &nonce, plaintext, aad)?;

    Ok((ciphertext, nonce))
}

fn encrypt_with_generated_nonce(
    key: &AeadKey,
    nonce: &XChaCha20Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Ciphertext> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(nonce.as_slice());
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| AeadError::Encrypt)?;

    Ok(Ciphertext(ciphertext))
}

/// Encrypt plaintext with a caller-supplied nonce for known-answer tests.
///
/// This API is only compiled in test builds. Production encryption uses
/// `encrypt`, which generates the nonce internally.
#[cfg(test)]
pub fn encrypt_with_nonce(
    key: &AeadKey,
    nonce: &XChaCha20Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Ciphertext> {
    encrypt_with_generated_nonce(key, nonce, plaintext, aad)
}

/// Decrypt and authenticate AEAD_XCHACHA20_POLY1305_V1 ciphertext.
///
/// # Contract
/// ## Preconditions
/// - `key` is the same 32-byte `AeadKey` used for encryption.
/// - `nonce` is the same 24-byte `XChaCha20Nonce` used for encryption.
/// - `ciphertext` contains `ciphertext_bytes || tag` and must be at least
///   `TAG_LEN` bytes long.
/// - `aad` is byte-for-byte identical to the canonical AAD supplied at
///   encryption time.
/// ## Postconditions
/// - On success, returns the complete authenticated `Plaintext`.
/// - On authentication failure, malformed input, or any backend failure,
///   returns `Err`.
/// - On failure, never returns partial plaintext.
/// ## Invariants
/// - Uses no custom cryptographic primitive; implementation must use the
///   `chacha20poly1305` crate.
/// - All AEAD operations authenticate associated data.
/// - Secret values are not logged, printed, written, or compared with `==`.
pub fn decrypt(
    key: &AeadKey,
    nonce: &XChaCha20Nonce,
    ciphertext: &Ciphertext,
    aad: &[u8],
) -> Result<Plaintext> {
    if ciphertext.as_ref().len() < TAG_LEN {
        return Err(AeadError::Decrypt);
    }

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(nonce.as_slice());
    let payload = Payload {
        msg: ciphertext.as_ref(),
        aad,
    };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| AeadError::Decrypt)?;

    Ok(Plaintext(plaintext))
}

/// Generate a production XChaCha20-Poly1305 nonce.
///
/// # Contract
/// ## Preconditions
/// - The operating system CSPRNG is available.
/// - Callers do not provide entropy or override the randomness source.
/// ## Postconditions
/// - Returns exactly one 24-byte `XChaCha20Nonce`.
/// - The nonce bytes are generated by the OS CSPRNG.
/// ## Invariants
/// - Uses no custom RNG and no deterministic nonce derivation.
/// - The randomness source is centralized and non-overridable in production.
/// - Nonce material is represented by `XChaCha20Nonce`, not raw fixed arrays in
///   the public API.
pub fn generate_nonce() -> XChaCha20Nonce {
    XChaCha20Nonce::from_bytes(crate::rng::random_nonce_xchacha20())
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn verify_encrypt_output_length() {
        let key = AeadKey::from_bytes(kani::any::<[u8; 32]>());
        let plaintext = kani::any::<[u8; 32]>();
        let aad = kani::any::<[u8; 74]>();
        let result = encrypt(&key, &plaintext, &aad);

        if let Ok((ciphertext, _nonce)) = result {
            kani::assert(
                ciphertext.as_ref().len() == plaintext.len() + TAG_LEN,
                "encrypt output is plaintext length plus tag",
            );
        }
    }

    #[kani::proof]
    fn verify_decrypt_rejects_short_input() {
        let key = AeadKey::from_bytes(kani::any::<[u8; 32]>());
        let nonce = XChaCha20Nonce::from_bytes(kani::any::<[u8; 24]>());
        let ciphertext = Ciphertext(vec![0u8; TAG_LEN - 1]);
        let aad = kani::any::<[u8; 74]>();
        let result = decrypt(&key, &nonce, &ciphertext, &aad);

        kani::assert(result.is_err(), "short ciphertext is rejected");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;

    const KEY_BYTES: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    const NONCE_BYTES: [u8; 24] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24,
    ];
    const AAD: [u8; 74] = [
        0x61, 0x72, 0x63, 0x61, 0x6e, 0x75, 0x6d, 0x2d, 0x61, 0x61, 0x64, 0x2d, 0x76, 0x31, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
        0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
        0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0x01, 0x00,
    ];
    const WRONG_AAD: [u8; 74] = [
        0x61, 0x72, 0x63, 0x61, 0x6e, 0x75, 0x6d, 0x2d, 0x61, 0x61, 0x64, 0x2d, 0x76, 0x31, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
        0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
        0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0x01, 0xff,
    ];
    const PLAINTEXT: [u8; 31] = [
        0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x2d, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x2d,
        0x66, 0x6f, 0x72, 0x2d, 0x61, 0x72, 0x63, 0x61, 0x6e, 0x75, 0x6d, 0x2d, 0x74, 0x65, 0x73,
        0x74,
    ];
    const EXPECTED_CIPHERTEXT_WITHOUT_TAG: [u8; 31] = [
        0x33, 0xce, 0x44, 0xa7, 0x1d, 0xb8, 0x13, 0x1d, 0xa9, 0x12, 0xd3, 0x0f, 0x5e, 0x8b, 0x57,
        0x8c, 0x48, 0x26, 0xe9, 0xbc, 0x44, 0x98, 0xe0, 0x24, 0x9a, 0x3c, 0x75, 0xc3, 0x6e, 0x8c,
        0x79,
    ];
    const EXPECTED_TAG: [u8; 16] = [
        0xd8, 0x95, 0x62, 0xcb, 0x06, 0x00, 0x88, 0xdb, 0xfe, 0xdc, 0xee, 0xc6, 0x7a, 0x54, 0xbc,
        0xb8,
    ];
    const EXPECTED_CIPHERTEXT_TAG: [u8; 47] = [
        0x33, 0xce, 0x44, 0xa7, 0x1d, 0xb8, 0x13, 0x1d, 0xa9, 0x12, 0xd3, 0x0f, 0x5e, 0x8b, 0x57,
        0x8c, 0x48, 0x26, 0xe9, 0xbc, 0x44, 0x98, 0xe0, 0x24, 0x9a, 0x3c, 0x75, 0xc3, 0x6e, 0x8c,
        0x79, 0xd8, 0x95, 0x62, 0xcb, 0x06, 0x00, 0x88, 0xdb, 0xfe, 0xdc, 0xee, 0xc6, 0x7a, 0x54,
        0xbc, 0xb8,
    ];

    #[test]
    fn test_encrypt_produces_expected_ciphertext_and_tag() {
        let key = AeadKey::from_bytes(KEY_BYTES);
        let nonce = XChaCha20Nonce::from_bytes(NONCE_BYTES);
        let ciphertext =
            encrypt_with_nonce(&key, &nonce, &PLAINTEXT, &AAD).expect("encrypt vector");

        assert_eq!(ciphertext.as_ref().len(), EXPECTED_CIPHERTEXT_TAG.len());
        assert_eq!(ciphertext.as_ref(), EXPECTED_CIPHERTEXT_TAG);
        assert_eq!(
            ciphertext
                .as_ref()
                .get(..EXPECTED_CIPHERTEXT_WITHOUT_TAG.len())
                .expect("ciphertext bytes range"),
            EXPECTED_CIPHERTEXT_WITHOUT_TAG
        );
        assert_eq!(
            ciphertext
                .as_ref()
                .get(EXPECTED_CIPHERTEXT_WITHOUT_TAG.len()..)
                .expect("tag bytes range"),
            EXPECTED_TAG
        );
    }

    #[test]
    fn test_decrypt_round_trip() {
        let key = AeadKey::from_bytes(KEY_BYTES);
        let nonce = XChaCha20Nonce::from_bytes(NONCE_BYTES);
        let ciphertext = Ciphertext(EXPECTED_CIPHERTEXT_TAG.to_vec());
        let plaintext = decrypt(&key, &nonce, &ciphertext, &AAD).expect("decrypt vector");

        assert!(bool::from(plaintext.as_ref().ct_eq(&PLAINTEXT)));
    }

    #[test]
    fn test_wrong_aad_rejected() {
        let key = AeadKey::from_bytes(KEY_BYTES);
        let nonce = XChaCha20Nonce::from_bytes(NONCE_BYTES);
        let ciphertext = Ciphertext(EXPECTED_CIPHERTEXT_TAG.to_vec());

        assert!(decrypt(&key, &nonce, &ciphertext, &WRONG_AAD).is_err());
    }

    #[test]
    fn test_truncated_ciphertext_rejected() {
        let key = AeadKey::from_bytes(KEY_BYTES);
        let nonce = XChaCha20Nonce::from_bytes(NONCE_BYTES);
        let ciphertext = Ciphertext(vec![0u8; TAG_LEN - 1]);

        assert!(decrypt(&key, &nonce, &ciphertext, &AAD).is_err());
    }

    #[test]
    fn test_empty_plaintext_ok() {
        let key = AeadKey::from_bytes(KEY_BYTES);
        let nonce = XChaCha20Nonce::from_bytes(NONCE_BYTES);
        let ciphertext =
            encrypt_with_nonce(&key, &nonce, &[], &AAD).expect("encrypt empty plaintext");

        assert_eq!(ciphertext.as_ref().len(), TAG_LEN);
    }
}
