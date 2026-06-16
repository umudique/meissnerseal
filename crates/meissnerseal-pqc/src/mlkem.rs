// SPDX-License-Identifier: Apache-2.0
//! ML-KEM-768 boundary for MeissnerSeal PQC operations.
//!
//! This module wraps RustCrypto `ml-kem` at the ML-KEM-768 parameter set and
//! exposes only fixed-length `Key<N>` values at the crate boundary.

use meissnerseal_crypto::types::Key;
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{
    array::Array, Decapsulate, Encapsulate, EncapsulationKey768, Kem, KeyExport, MlKem768,
};

pub type MlKemPublicKey = Key<1184>;
pub type MlKemPrivateKey = Key<2400>;
pub type MlKemCiphertext = Key<1088>;
pub type SharedSecret = Key<32>;

#[derive(Debug, thiserror::Error)]
pub enum MlKemError {
    #[error("ML-KEM backend unavailable")]
    BackendUnavailable,
    #[error("ML-KEM decapsulation failed")]
    DecapsulationFailed,
}

pub type Result<T> = core::result::Result<T, MlKemError>;

/// Generate a fresh ML-KEM-768 keypair.
///
/// # Contract
///
/// ## Preconditions
/// - The Phase 2 implementation must use the RustCrypto `ml-kem` backend with
///   the ML-KEM-768 parameter set selected by ADR-034.
/// - Randomness must come from the backend's OS-CSPRNG path; callers cannot
///   provide deterministic seed material in production builds.
///
/// ## Postconditions
/// - On success, returns a 1184-byte public key and a 2400-byte private key.
/// - On backend failure, returns `Err` and exposes no partial key material.
///
/// ## Invariants
/// - Private key material is held only in `Key<2400>`, which zeroizes on drop
///   and has redacted `Debug` output.
/// - This function never logs, prints, or writes key material.
pub fn keypair() -> Result<(MlKemPublicKey, MlKemPrivateKey)> {
    let (private_key, public_key) = MlKem768::generate_keypair();
    let public_key = key_from_slice(public_key.to_bytes().as_slice())?;
    #[allow(deprecated)]
    let private_key = key_from_slice(private_key.to_expanded_bytes().as_slice())?;
    Ok((public_key, private_key))
}

/// Encapsulate to an ML-KEM-768 public key.
///
/// # Contract
///
/// ## Preconditions
/// - `public_key` must be the complete 1184-byte ML-KEM-768 public key for the
///   recipient.
/// - The Phase 2 implementation must use the RustCrypto `ml-kem` backend and
///   its OS-CSPRNG encapsulation path.
///
/// ## Postconditions
/// - On success, returns a 1088-byte ciphertext and a 32-byte shared secret.
/// - On backend failure, returns `Err` and exposes no partial ciphertext or
///   shared secret.
///
/// ## Invariants
/// - Shared secret material is held only in `Key<32>`, which zeroizes on drop
///   and has redacted `Debug` output.
/// - No secret-dependent branch is introduced by this wrapper beyond the
///   underlying library's documented behavior.
/// - This function never logs, prints, or writes key material.
pub fn encapsulate(public_key: &MlKemPublicKey) -> Result<(MlKemCiphertext, SharedSecret)> {
    let public_key = EncapsulationKey768::new(array_ref_from_slice(public_key.as_slice())?)
        .map_err(|_| MlKemError::BackendUnavailable)?;
    let (ciphertext, shared_secret) = public_key.encapsulate();

    let ciphertext = key_from_slice(ciphertext.as_slice())?;
    let shared_secret = key_from_slice(shared_secret.as_slice())?;

    Ok((ciphertext, shared_secret))
}

/// Decapsulate an ML-KEM-768 ciphertext with the recipient private key.
///
/// # Contract
///
/// ## Preconditions
/// - `private_key` must be the complete 2400-byte ML-KEM-768 private key.
/// - `ciphertext` must be the complete 1088-byte ML-KEM-768 ciphertext.
///
/// ## Postconditions
/// - On valid input, returns the same 32-byte shared secret produced by
///   `encapsulate` for the corresponding public key.
/// - On same-length tampered ciphertext, FIPS 203 §6.3 implicit rejection
///   applies: returns `Ok` with a pseudorandom shared secret derived from a
///   secret seed in the private key. The tampered secret differs from the
///   original with overwhelming probability. No `Err` is returned and no
///   information about the tampering is leaked (prevents decryption oracle).
/// - `Err` is returned only on structural failure (wrong-length slice input),
///   which the `Key<N>` type prevents at this crate boundary.
///
/// ## Invariants
/// - Private key and shared secret material are held only in fixed-length
///   `Key<N>` wrappers with zeroize-on-drop and redacted `Debug`.
/// - This function does not compare secret values with `==`; callers must use
///   `Key::ct_eq` for secret equality checks.
/// - This function never logs, prints, or writes key material.
pub fn decapsulate(
    private_key: &MlKemPrivateKey,
    ciphertext: &MlKemCiphertext,
) -> Result<SharedSecret> {
    #[allow(deprecated)]
    let private_key = <ml_kem::DecapsulationKey768 as ExpandedKeyEncoding>::from_expanded_bytes(
        array_ref_from_slice(private_key.as_slice())?,
    )
    .map_err(|_| MlKemError::BackendUnavailable)?;

    let ciphertext = array_ref_from_slice(ciphertext.as_slice())?;
    let shared_secret = private_key.decapsulate(ciphertext);

    key_from_slice(shared_secret.as_slice())
}

fn key_from_slice<const N: usize>(slice: &[u8]) -> Result<Key<N>> {
    let bytes: [u8; N] = slice
        .try_into()
        .map_err(|_| MlKemError::BackendUnavailable)?;
    Ok(Key::from_bytes(bytes))
}

fn array_ref_from_slice<U>(slice: &[u8]) -> Result<&Array<u8, U>>
where
    U: ml_kem::ArraySize,
{
    <&Array<u8, U>>::try_from(slice).map_err(|_| MlKemError::BackendUnavailable)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use zeroize::Zeroize;
    use zeroize::Zeroizing;

    #[test]
    fn keypair_sizes_correct() {
        let (public_key, private_key) = keypair().expect("Phase 2 keypair succeeds");
        assert_eq!(public_key.as_slice().len(), 1184);
        assert_eq!(private_key.as_slice().len(), 2400);
    }

    #[test]
    fn encapsulate_output_sizes_correct() {
        let (public_key, _private_key) = keypair().expect("Phase 2 keypair succeeds");
        let (ciphertext, shared_secret) =
            encapsulate(&public_key).expect("Phase 2 encapsulate succeeds");

        assert_eq!(ciphertext.as_slice().len(), 1088);
        assert_eq!(shared_secret.as_slice().len(), 32);
    }

    #[test]
    fn decapsulate_valid_matches_encapsulate_shared_secret() {
        let (public_key, private_key) = keypair().expect("Phase 2 keypair succeeds");
        let (ciphertext, encapsulated_secret) =
            encapsulate(&public_key).expect("Phase 2 encapsulate succeeds");
        let decapsulated_secret =
            decapsulate(&private_key, &ciphertext).expect("Phase 2 decapsulate succeeds");

        assert!(bool::from(encapsulated_secret.ct_eq(&decapsulated_secret)));
    }

    #[test]
    fn decapsulate_tampered_ciphertext_returns_different_secret() {
        let (public_key, private_key) = keypair().expect("keypair succeeds");
        let (ciphertext, original_secret) = encapsulate(&public_key).expect("encapsulate succeeds");
        let mut bytes = *ciphertext.as_bytes();
        if let Some(first) = bytes.first_mut() {
            *first ^= 0x80;
        }
        let tampered = MlKemCiphertext::from_bytes(bytes);
        // FIPS 203 §6.3 implicit rejection: tampered ciphertext → Ok with a
        // pseudorandom secret, not Err. Returning Err would be an oracle.
        let tampered_secret =
            decapsulate(&private_key, &tampered).expect("implicit rejection returns Ok");
        assert!(bool::from(!original_secret.ct_eq(&tampered_secret)));
    }

    #[test]
    fn shared_secret_memory_is_zeroize_on_drop_wrapped() {
        let mut secret = Zeroizing::new(SharedSecret::from_bytes([0xA5; 32]));
        assert_eq!(secret.as_slice().len(), 32);
        secret.zeroize();
        assert!(secret.as_slice().iter().all(|byte| *byte == 0));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn key_types_have_mlkem768_lengths() {
        kani::assert(MlKemPublicKey::LEN == 1184, "ML-KEM-768 public key length");
        kani::assert(
            MlKemPrivateKey::LEN == 2400,
            "ML-KEM-768 private key length",
        );
        kani::assert(MlKemCiphertext::LEN == 1088, "ML-KEM-768 ciphertext length");
        kani::assert(SharedSecret::LEN == 32, "ML-KEM shared secret length");
    }

    #[kani::proof]
    fn shared_secret_ct_eq_is_total_for_fixed_length_inputs() {
        let a = SharedSecret::from_bytes(kani::any::<[u8; 32]>());
        let b = SharedSecret::from_bytes(kani::any::<[u8; 32]>());
        let _ = a.ct_eq(&b);
    }

    #[kani::proof]
    fn decapsulate_input_boundary_lengths() {
        // Proves compile-time length constants match FIPS 203 §7.2 ML-KEM-768.
        // No symbolic Key<N> allocation — large arrays (2400, 1088 bytes) cause
        // Kani to unwind the zeroize drop loop thousands of times. LEN constants
        // are evaluated at compile time; no loop unwinding occurs.
        // Full decapsulate() is not called — ml-kem NTT loops (degree 256) exceed
        // any practical bounded-unwind budget. See ADR-012 for audit scope.
        kani::assert(MlKemPrivateKey::LEN == 2400, "private key is 2400 bytes");
        kani::assert(MlKemCiphertext::LEN == 1088, "ciphertext is 1088 bytes");
    }

    #[kani::proof]
    fn shared_secret_zeroize_contract_stub() {
        // Boundary proof: the fixed-length shared-secret wrapper can be
        // explicitly zeroized; backend internals remain outside this crate.
        let mut secret = SharedSecret::from_bytes(kani::any::<[u8; 32]>());
        zeroize::Zeroize::zeroize(&mut secret);
    }
}
