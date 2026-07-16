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
use zeroize::Zeroizing;

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
    let expanded = Zeroizing::new(private_key.to_expanded_bytes());
    let private_key = key_from_slice(expanded.as_slice())?;
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
    let shared_secret = Zeroizing::new(shared_secret);
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
    let shared_secret = Zeroizing::new(private_key.decapsulate(ciphertext));
    key_from_slice(shared_secret.as_slice())
}

fn key_from_slice<const N: usize>(slice: &[u8]) -> Result<Key<N>> {
    let bytes: [u8; N] = slice
        .try_into()
        .map_err(|_| MlKemError::BackendUnavailable)?;
    // Wrap in Zeroizing before passing to Key::from_bytes so the stack copy
    // of secret material (private key, shared secret) is wiped on drop.
    let bytes = Zeroizing::new(bytes);
    Ok(Key::from_bytes(*bytes))
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
    use serde::Deserialize;
    use serde::Deserializer;
    use std::mem::ManuallyDrop;
    use std::slice;
    use zeroize::Zeroize;
    use zeroize::Zeroizing;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct KatFile {
        #[serde(rename = "schema", deserialize_with = "deserialize_mlkem_kat_schema")]
        _schema: String,
        #[serde(rename = "description")]
        _description: String,
        #[serde(rename = "m_usage_note")]
        _m_usage_note: String,
        #[serde(rename = "source")]
        _source: KatSource,
        vectors: Vec<KatVector>,
        val_group: ValGroup,
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    #[serde(deny_unknown_fields)]
    struct KatSource {
        name: String,
        repository: String,
        file: String,
        commit: String,
        algorithm: String,
        #[serde(rename = "testType")]
        test_type: String,
        #[serde(rename = "tcIds")]
        tc_ids: Vec<usize>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct KatVector {
        #[serde(rename = "tcId")]
        tc_id: usize,
        #[serde(deserialize_with = "deserialize_hex_string")]
        ek: String,
        #[serde(deserialize_with = "deserialize_hex_string")]
        dk: String,
        #[serde(deserialize_with = "deserialize_hex_string")]
        c: String,
        #[serde(default, deserialize_with = "deserialize_optional_hex_string")]
        k: Option<String>,
        #[serde(
            rename = "m",
            default,
            deserialize_with = "deserialize_optional_hex_string"
        )]
        _m: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ValGroup {
        #[serde(rename = "tgId")]
        _tg_id: usize,
        #[serde(rename = "testType")]
        _test_type: String,
        #[serde(rename = "parameterSet")]
        _parameter_set: String,
        #[serde(rename = "function")]
        _function: String,
        #[serde(deserialize_with = "deserialize_hex_string")]
        dk: String,
        #[serde(rename = "ek", deserialize_with = "deserialize_hex_string")]
        _ek: String,
        tests: Vec<ValCase>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ValCase {
        #[serde(rename = "tcId")]
        tc_id: usize,
        #[serde(rename = "deferred")]
        _deferred: bool,
        #[serde(deserialize_with = "deserialize_hex_string")]
        c: String,
        #[serde(deserialize_with = "deserialize_hex_string")]
        k: String,
        #[serde(rename = "reason")]
        _reason: String,
    }

    fn deserialize_hex_string<'de, D>(deserializer: D) -> core::result::Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() % 2 != 0 {
            return Err(serde::de::Error::custom("hex string must have even length"));
        }
        if !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            return Err(serde::de::Error::custom(
                "hex string contains non-hex digit",
            ));
        }
        Ok(value)
    }

    fn deserialize_mlkem_kat_schema<'de, D>(
        deserializer: D,
    ) -> core::result::Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value != "mlkem-768-kat-v1" {
            return Err(serde::de::Error::custom("schema must be mlkem-768-kat-v1"));
        }
        Ok(value)
    }

    fn deserialize_optional_hex_string<'de, D>(
        deserializer: D,
    ) -> core::result::Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|value| {
                if value.len() % 2 != 0 {
                    return Err(serde::de::Error::custom("hex string must have even length"));
                }
                if !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
                    return Err(serde::de::Error::custom(
                        "hex string contains non-hex digit",
                    ));
                }
                Ok(value)
            })
            .transpose()
    }

    fn from_hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0, "hex string must have even length: {}", s);
        s.as_bytes()
            .chunks(2)
            .map(|pair| {
                let hex = std::str::from_utf8(pair).expect("valid utf8");
                u8::from_str_radix(hex, 16).expect("valid hex")
            })
            .collect()
    }

    fn load_kat() -> KatFile {
        serde_json::from_str(KAT).expect("mlkem_768_kat_v1.json must be valid")
    }

    fn find_vector(kat: &KatFile, tc_id: usize) -> &KatVector {
        kat.vectors
            .iter()
            .find(|vector| vector.tc_id == tc_id)
            .expect("tcId must exist")
    }

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

    #[test]
    #[ignore = "Meaningful under Miri: validates drop-path zeroization after destruction."]
    #[allow(unsafe_code)]
    fn shared_secret_drop_zeroizes_backing_bytes() {
        let secret = SharedSecret::from_bytes([0xA5; 32]);
        let mut secret = ManuallyDrop::new(secret);
        let ptr = secret.as_bytes().as_ptr();

        // SAFETY: `ptr` is captured from the allocation owned by `secret`.
        // This test is ignored in normal runs and intended for Miri, where
        // reading the bytes after drop is used to validate zeroization of the
        // same backing storage.
        unsafe { // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            ManuallyDrop::drop(&mut secret);
            let bytes = slice::from_raw_parts(ptr, SharedSecret::LEN);
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    #[should_panic(expected = "hex string must have even length")]
    fn from_hex_rejects_odd_length_input() {
        let _ = from_hex("abc");
    }

    // NIST FIPS 203 ML-KEM-768 Known-Answer Tests (F-20)
    // Source: NIST ACVP-Server ML-KEM-encapDecap-FIPS203/internalProjection.json
    // commit 65370b8, tcIds 26-28, ML-KEM-768 AFT vectors.
    // dk field is the 2400-byte FIPS 203 §5.3 expanded format (dk_PKE || ek || H(ek) || z).
    // Verifies: decapsulate(dk, c) == k for all three vectors.

    const KAT: &str = include_str!("../../../test-vectors/mlkem_768_kat_v1.json");

    // F-55: encapsulate boundary — adversarial public keys must not panic.
    // ML-KEM has no "invalid" 1184-byte public key (any bytes are structurally
    // valid); this test verifies the boundary handles edge-case inputs gracefully.
    #[test]
    fn encapsulate_adversarial_keys_do_not_panic() {
        let _ = encapsulate(&MlKemPublicKey::from_bytes([0u8; 1184]));
        let _ = encapsulate(&MlKemPublicKey::from_bytes([0xffu8; 1184]));
        let incrementing = core::array::from_fn(|index| {
            u8::try_from(index % (usize::from(u8::MAX) + 1)).expect("mod 256 fits into u8")
        });
        let _ = encapsulate(&MlKemPublicKey::from_bytes(incrementing));
        let low_order_like = {
            let mut bytes = [0u8; 1184];
            bytes[0] = 0x01;
            bytes
        };
        let _ = encapsulate(&MlKemPublicKey::from_bytes(low_order_like));
    }

    #[test]
    fn adversarial_public_key_length_boundary_is_rejected() {
        let short = vec![0x5a; 1183];
        assert!(matches!(
            super::key_from_slice::<1184>(&short),
            Err(MlKemError::BackendUnavailable)
        ));
    }

    #[test]
    fn kat_loader_rejects_malformed_fields() {
        let missing_colon = r#"{"vectors":[{"tcId":26,"ek" "aa","dk":"bb","c":"cc","k":"dd"}],"val_group":{"dk":"00","tests":[]}}"#;
        assert!(serde_json::from_str::<KatFile>(missing_colon).is_err());

        let bad_hex = r#"{"vectors":[{"tcId":26,"ek":"zz","dk":"00","c":"00","k":"00"}],"val_group":{"dk":"00","tests":[]}}"#;
        assert!(serde_json::from_str::<KatFile>(bad_hex).is_err());
    }

    #[test]
    fn kat_loader_rejects_wrong_schema() {
        let bad_schema = r#"{
            "schema":"not-mlkem-768-kat-v1",
            "description":"bad schema",
            "m_usage_note":"test",
            "source":"test",
            "vectors":[],
            "val_group":{"dk":"00","tests":[]}
        }"#;
        assert!(
            serde_json::from_str::<KatFile>(bad_schema).is_err(),
            "typed KAT loader must reject an unexpected schema tag"
        );
    }

    // F-55: encapsulate cross-verify — using NIST key material confirms that
    // encapsulate() produces ciphertexts that decapsulate() can recover, closing
    // the gap between the one-sided NIST KAT vectors (decapsulation only).
    #[test]
    fn encapsulate_with_nist_ek_consistent_with_dk() {
        let kat = load_kat();
        for tc_id in [26usize, 27, 28] {
            let vector = find_vector(&kat, tc_id);
            let ek_hex = &vector.ek;
            let dk_hex = &vector.dk;

            let ek_bytes: [u8; 1184] = from_hex(ek_hex).try_into().expect("ek 1184 bytes");
            let dk_bytes: [u8; 2400] = from_hex(dk_hex).try_into().expect("dk 2400 bytes");

            let public_key = MlKemPublicKey::from_bytes(ek_bytes);
            let private_key = MlKemPrivateKey::from_bytes(dk_bytes);

            let (ciphertext, encap_secret) =
                encapsulate(&public_key).expect("NIST KAT ek encapsulate succeeds");
            let decap_secret =
                decapsulate(&private_key, &ciphertext).expect("round-trip decapsulate succeeds");

            assert!(
                bool::from(encap_secret.ct_eq(&decap_secret)),
                "tcId {tc_id}: encapsulate/decapsulate shared secret mismatch"
            );
        }
    }

    #[test]
    fn nist_kat_decapsulate() {
        let kat = load_kat();
        // Vectors tcId 26, 27, 28 from NIST ACVP internalProjection.json.
        for tc_id in [26usize, 27, 28] {
            let vector = find_vector(&kat, tc_id);
            let dk_hex = &vector.dk;
            let c_hex = &vector.c;
            let k_hex = vector.k.as_ref().expect("positive KAT must carry k");

            let dk_bytes: [u8; 2400] = from_hex(dk_hex).try_into().expect("dk 2400 bytes");
            let c_bytes: [u8; 1088] = from_hex(c_hex).try_into().expect("c 1088 bytes");
            let k_bytes: [u8; 32] = from_hex(k_hex).try_into().expect("k 32 bytes");

            let private_key = MlKemPrivateKey::from_bytes(dk_bytes);
            let ciphertext = MlKemCiphertext::from_bytes(c_bytes);

            let shared_secret =
                decapsulate(&private_key, &ciphertext).expect("NIST KAT decapsulate succeeds");

            assert_eq!(
                shared_secret.as_slice(),
                k_bytes.as_slice(),
                "tcId {tc_id}: decapsulate output does not match NIST known answer"
            );
        }
    }

    // NIST ACVP VAL vectors (tgId=5, ML-KEM-768, commit 65370b8).
    // Shared dk at group level; per-test c and k.
    // "modify ciphertext" cases: FIPS 203 §6.3 implicit rejection —
    //   decapsulate(dk, tampered_c) must return a deterministic pseudorandom
    //   K' (not Err), preventing chosen-ciphertext oracle attacks.
    // "no modification" cases: normal decapsulation positive KATs.
    #[test]
    #[cfg_attr(miri, ignore = "serde_json triggers memchr SSE2 alignment UB under Miri")]
    fn nist_val_implicit_rejection_and_positive_decapsulate() {
        let kat = load_kat();
        let dk_hex = &kat.val_group.dk;
        let dk_bytes: [u8; 2400] = from_hex(dk_hex).try_into().expect("val dk 2400 bytes");
        let private_key = MlKemPrivateKey::from_bytes(dk_bytes);

        for case in &kat.val_group.tests {
            let c_bytes: [u8; 1088] = from_hex(&case.c)
                .try_into()
                .expect("VAL tcId c must be 1088 bytes");
            let k_bytes: [u8; 32] = from_hex(&case.k)
                .try_into()
                .expect("VAL tcId k must be 32 bytes");
            let ciphertext = MlKemCiphertext::from_bytes(c_bytes);
            // FIPS 203 §6.3: decapsulate never returns Err — it returns either
            // the real shared secret (valid c) or a pseudorandom K' (tampered c).
            let result = decapsulate(&private_key, &ciphertext)
                .expect("decapsulate must not return Err (FIPS 203 §6.3 implicit rejection)");
            assert_eq!(
                result.as_slice(),
                k_bytes.as_slice(),
                "tcId {}: decapsulate output does not match NIST VAL known answer",
                case.tc_id
            );
        }
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
