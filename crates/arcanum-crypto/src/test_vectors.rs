//! Known-answer test-vector consumption for arcanum-crypto (finding A1).
//!
//! Each `#[test]` deserializes a `test-vectors/*.json` file and asserts the
//! crate's real public API reproduces every expected value (positives) or
//! rejects every malformed input (negatives). The vectors are independently
//! cross-verified by `test-vectors/cross_verify.py`.
//!
//! Secret/key comparisons use `subtle::ConstantTimeEq` and never print bytes;
//! failure messages reference only the case id. The vectors carry no real
//! secrets.

#[cfg(test)]
// REASON: vector-consumption tests parse fixed, non-secret KAT JSON and hex and
// drive the test-only `encrypt_with_nonce` API. Indexing, unchecked arithmetic,
// casts, and expect/panic/unwrap are acceptable in this test-only code, which
// never ships in a release binary.
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]
mod tests {
    use crate::aead::{decrypt, encrypt_with_nonce, Ciphertext};
    use crate::kdf::argon2::{derive, derive_vkek, Argon2Params};
    use crate::kdf::hkdf::{derive_root_prk, derive_subkey, Prk, SubkeyPurpose};
    use crate::types::{AeadKey, HeaderNonce, Key, MasterUnlockKey, VaultRootKey, XChaCha20Nonce};
    use serde_json::Value;
    use std::path::PathBuf;
    use subtle::ConstantTimeEq;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn vectors_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors")
    }

    fn load(name: &str) -> Value {
        let path = vectors_dir().join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_str(&text).expect("valid JSON vector file")
    }

    fn unhex(s: &str) -> Vec<u8> {
        assert!(
            s.len().is_multiple_of(2),
            "hex string must have even length"
        );
        s.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).expect("hex digit");
                let lo = (pair[1] as char).to_digit(16).expect("hex digit");
                ((hi << 4) | lo) as u8
            })
            .collect()
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        <[u8; N]>::try_from(unhex(s).as_slice()).expect("fixed-width hex field")
    }

    fn find<'a>(v: &'a Value, id: &str) -> &'a Value {
        v["cases"]
            .as_array()
            .expect("cases array")
            .iter()
            .find(|c| c["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("missing case {id}"))
    }

    fn str_in<'a>(c: &'a Value, key: &str) -> &'a str {
        c["inputs"][key]
            .as_str()
            .unwrap_or_else(|| panic!("missing input {key}"))
    }

    fn u64_in(c: &Value, key: &str) -> u64 {
        c["inputs"][key]
            .as_u64()
            .unwrap_or_else(|| panic!("missing input {key}"))
    }

    /// Constant-time assert that a derived 32-byte key equals the expected bytes.
    fn assert_key32(actual: &Key<32>, expected_hex: &str, case: &str) {
        let expected = Key::<32>::from_bytes(arr::<32>(expected_hex));
        assert!(
            bool::from(actual.ct_eq(&expected)),
            "case {case}: key mismatch"
        );
    }

    // ── vault_kdf_v1.json — Argon2id + HKDF derivation chain ─────────────────

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn vault_kdf_v1_vectors() {
        let v = load("vault_kdf_v1.json");

        // MUK: Argon2id(password, vault_id, params)
        let c = find(&v, "muk-derivation");
        let password = str_in(c, "password").as_bytes().to_vec();
        let vault_id = arr::<16>(str_in(c, "vault_id"));
        let params = Argon2Params {
            m_cost_kib: u64_in(c, "m_cost_kib") as u32,
            t_cost: u64_in(c, "t_cost") as u32,
            p_lanes: u64_in(c, "p_lanes") as u32,
            output_len: u64_in(c, "output_len") as usize,
        };
        let muk = derive(&password, &vault_id, &params).expect("MUK derivation");
        assert_key32(
            &muk,
            c["expected"]["master_unlock_key"].as_str().unwrap(),
            "muk-derivation",
        );

        // VKEK: HKDF(MUK)
        let c = find(&v, "vkek-derivation");
        let muk_in = MasterUnlockKey::from_bytes(arr::<32>(str_in(c, "master_unlock_key")));
        let vault_id = arr::<16>(str_in(c, "vault_id"));
        let vkek = derive_vkek(&muk_in, &vault_id).expect("VKEK derivation");
        assert_key32(
            &vkek,
            c["expected"]["vault_key_encryption_key"].as_str().unwrap(),
            "vkek-derivation",
        );

        // root_prk: SHA256(domain||vault_id||header_nonce) -> HKDF-Extract(VRK)
        let c = find(&v, "root-prk-derivation");
        let vrk = VaultRootKey::from_bytes(arr::<32>(str_in(c, "vault_root_key")));
        let vault_id = arr::<16>(str_in(c, "vault_id"));
        let header_nonce = HeaderNonce::from_bytes(arr::<24>(str_in(c, "header_nonce")));
        let root_prk = derive_root_prk(&vrk, &vault_id, &header_nonce);
        assert_key32(
            &root_prk,
            c["expected"]["root_prk"].as_str().unwrap(),
            "root-prk-derivation",
        );

        // subkeys: HKDF-Expand per purpose
        let c = find(&v, "subkey-derivation");
        let root_prk = Prk::from_bytes(arr::<32>(str_in(c, "root_prk")));
        let vault_id = arr::<16>(str_in(c, "vault_id"));
        let aead_id = u64_in(c, "aead_id") as u16;
        let expected = &c["expected"];
        let registry: [(&str, SubkeyPurpose, Option<u16>); 7] = [
            (
                "item_key_wrapping_key",
                SubkeyPurpose::ItemKeyWrappingKey,
                Some(aead_id),
            ),
            (
                "metadata_encryption_key",
                SubkeyPurpose::MetadataEncryptionKey,
                Some(aead_id),
            ),
            (
                "local_audit_event_key",
                SubkeyPurpose::LocalAuditEventKey,
                None,
            ),
            ("sync_envelope_key", SubkeyPurpose::SyncEnvelopeKey, None),
            (
                "device_enrollment_key",
                SubkeyPurpose::DeviceEnrollmentKey,
                None,
            ),
            (
                "recovery_wrapping_key",
                SubkeyPurpose::RecoveryWrappingKey,
                None,
            ),
            ("export_bundle_key", SubkeyPurpose::ExportBundleKey, None),
        ];
        for (name, purpose, aead) in registry {
            let subkey = derive_subkey(&root_prk, purpose, &vault_id, aead).expect("subkey");
            assert_key32(&subkey, expected[name].as_str().unwrap(), name);
        }
    }

    // ── aead_xchacha20_v1.json — XChaCha20-Poly1305 KATs ─────────────────────

    #[test]
    fn aead_xchacha20_v1_vectors() {
        let v = load("aead_xchacha20_v1.json");

        // Positive: fixed-nonce encrypt reproduces ciphertext || tag.
        let c = find(&v, "xchacha20-basic-encrypt");
        let key = AeadKey::from_bytes(arr::<32>(str_in(c, "key")));
        let nonce = XChaCha20Nonce::from_bytes(arr::<24>(str_in(c, "nonce")));
        let plaintext = unhex(str_in(c, "plaintext"));
        let aad = unhex(str_in(c, "aad"));
        let ciphertext = encrypt_with_nonce(&key, &nonce, &plaintext, &aad).expect("encrypt");
        let mut expected = unhex(c["expected"]["ciphertext"].as_str().unwrap());
        expected.extend_from_slice(&unhex(c["expected"]["tag"].as_str().unwrap()));
        assert_eq!(
            ciphertext.as_ref(),
            expected.as_slice(),
            "case xchacha20-basic-encrypt"
        );

        // Positive: decrypt round-trip recovers the plaintext.
        let c = find(&v, "xchacha20-decrypt-round-trip");
        let key = AeadKey::from_bytes(arr::<32>(str_in(c, "key")));
        let nonce = XChaCha20Nonce::from_bytes(arr::<24>(str_in(c, "nonce")));
        let ciphertext = Ciphertext::from(unhex(str_in(c, "ciphertext_tag")));
        let aad = unhex(str_in(c, "aad"));
        let plaintext = decrypt(&key, &nonce, &ciphertext, &aad).expect("decrypt");
        let expected_pt = unhex(c["expected"]["plaintext"].as_str().unwrap());
        assert!(
            bool::from(plaintext.as_ref().ct_eq(expected_pt.as_slice())),
            "case xchacha20-decrypt-round-trip"
        );

        // Negatives: wrong AAD, tampered ciphertext (C1), tampered tag (C2),
        // wrong key (C3) — decrypt must fail closed.
        for id in [
            "xchacha20-wrong-aad-rejected",
            "c1-tampered-ciphertext-rejected",
            "c2-tampered-tag-rejected",
            "c3-wrong-key-rejected",
        ] {
            let c = find(&v, id);
            assert_eq!(
                c["expected"]["result"].as_str(),
                Some("Err"),
                "case {id}: expects Err"
            );
            let key = AeadKey::from_bytes(arr::<32>(str_in(c, "key")));
            let nonce = XChaCha20Nonce::from_bytes(arr::<24>(str_in(c, "nonce")));
            let ciphertext = Ciphertext::from(unhex(str_in(c, "ciphertext_tag")));
            let aad = unhex(str_in(c, "aad"));
            assert!(
                decrypt(&key, &nonce, &ciphertext, &aad).is_err(),
                "case {id}: decrypt must reject"
            );
        }

        // Positive edge: empty-plaintext encrypt yields a 16-byte tag only.
        let c = find(&v, "c4-empty-plaintext-encrypt");
        let key = AeadKey::from_bytes(arr::<32>(str_in(c, "key")));
        let nonce = XChaCha20Nonce::from_bytes(arr::<24>(str_in(c, "nonce")));
        let aad = unhex(str_in(c, "aad"));
        let ciphertext = encrypt_with_nonce(&key, &nonce, &[], &aad).expect("encrypt empty");
        let expected = unhex(c["expected"]["ciphertext_tag"].as_str().unwrap());
        assert_eq!(
            ciphertext.as_ref(),
            expected.as_slice(),
            "case c4-empty-plaintext-encrypt"
        );
    }

    // ── vault_wrap_v1.json — WrappedRootKey wrap/unwrap + domain separation ──

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn vault_wrap_v1_vectors() {
        let v = load("vault_wrap_v1.json");

        // wrap-vrk-roundtrip: encrypt VRK under VKEK + WrappedRootKey AAD.
        let c = find(&v, "wrap-vrk-roundtrip");
        let vkek = AeadKey::from_bytes(arr::<32>(str_in(c, "vault_kek")));
        let nonce = XChaCha20Nonce::from_bytes(arr::<24>(str_in(c, "vkek_nonce")));
        let aad = unhex(str_in(c, "wrap_aad"));
        let vrk = unhex(str_in(c, "vault_root_key"));
        let wrapped = encrypt_with_nonce(&vkek, &nonce, &vrk, &aad).expect("wrap VRK");
        let expected_wrapped = unhex(c["expected"]["wrapped_root_key"].as_str().unwrap());
        assert_eq!(
            wrapped.as_ref(),
            expected_wrapped.as_slice(),
            "case wrap-vrk-roundtrip: wrapped"
        );
        let unwrapped = decrypt(&vkek, &nonce, &wrapped, &aad).expect("unwrap VRK");
        assert!(
            bool::from(unwrapped.as_ref().ct_eq(vrk.as_slice())),
            "case wrap-vrk-roundtrip: unwrap round-trip"
        );

        // B3: distinct vault_id -> distinct VKEK -> distinct WrappedRootKey.
        let c = find(&v, "wrap-vrk-cross-vault-domain-separation");
        let vkek2 = AeadKey::from_bytes(arr::<32>(str_in(c, "vault_kek")));
        let nonce2 = XChaCha20Nonce::from_bytes(arr::<24>(str_in(c, "vkek_nonce")));
        let aad2 = unhex(str_in(c, "wrap_aad"));
        let vrk2 = unhex(str_in(c, "vault_root_key"));
        let wrapped2 = encrypt_with_nonce(&vkek2, &nonce2, &vrk2, &aad2).expect("wrap VRK vault2");
        let expected_wrapped2 = unhex(c["expected"]["wrapped_root_key"].as_str().unwrap());
        assert_eq!(
            wrapped2.as_ref(),
            expected_wrapped2.as_slice(),
            "case wrap-vrk-cross-vault-domain-separation: wrapped"
        );
        assert_ne!(
            wrapped2.as_ref(),
            expected_wrapped.as_slice(),
            "case wrap-vrk-cross-vault-domain-separation: must differ from vault1"
        );

        // B4: a different password yields a distinct MUK and VKEK (recomputed).
        let c = find(&v, "wrong-password-muk-distinct");
        let password = str_in(c, "password").as_bytes().to_vec();
        let vault_id = arr::<16>(str_in(c, "vault_id"));
        let params = Argon2Params {
            m_cost_kib: 65_536,
            t_cost: 3,
            p_lanes: 4,
            output_len: 32,
        };
        let muk = derive(&password, &vault_id, &params).expect("MUK derivation");
        assert_key32(
            &muk,
            c["expected"]["master_unlock_key"].as_str().unwrap(),
            "wrong-password-muk-distinct: muk",
        );
        let vkek = derive_vkek(&muk, &vault_id).expect("VKEK derivation");
        assert_key32(
            &vkek,
            c["expected"]["vault_key_encryption_key"].as_str().unwrap(),
            "wrong-password-muk-distinct: vkek",
        );
    }
}
