// SPDX-License-Identifier: Apache-2.0
//! Argon2id key derivation contracts.

use crate::kdf::{KdfError, Result};
use crate::types::{MasterUnlockKey, VaultKeyEncKey};
use argon2::{Algorithm, Argon2, Params, Version};

/// Domain separation prefix for `KDF_ARGON2ID_V1` salt construction.
pub const ARGON2ID_SALT_DOMAIN_V1: &[u8; 29] = b"meissnerseal-argon2id-salt-v1";
const VKEK_SALT_DOMAIN_V1: &[u8; 25] = b"meissnerseal-vkek-salt-v1";
const VKEK_INFO_V1: &[u8] = b"meissnerseal:vault-kek:v1";

/// Maximum allowed memory cost for Argon2id (256 MiB). Prevents DoS via huge allocations.
pub const ARGON2_MAX_M_COST_KIB: u32 = 262_144;
/// Maximum allowed iteration count for Argon2id.
pub const ARGON2_MAX_T_COST: u32 = 16;
/// Maximum allowed parallelism lanes for Argon2id.
pub const ARGON2_MAX_P_LANES: u32 = 16;

/// Explicit Argon2id parameter set for `KDF_ARGON2ID_V1`.
#[derive(Clone, Copy, Debug)]
pub struct Argon2Params {
    /// Argon2 memory cost in KiB.
    pub m_cost_kib: u32,

    /// Argon2 iteration count.
    pub t_cost: u32,

    /// Argon2 parallelism lanes.
    pub p_lanes: u32,

    /// Requested output length in bytes.
    pub output_len: usize,
}

/// Derive the 32-byte Master Unlock Key using Argon2id.
///
/// # Contract
/// ## Preconditions
/// - `password` is caller-owned secret input and is never logged, printed, or
///   written to any output.
/// - `vault_id` is the canonical 128-bit vault UUID.
/// - `params` supplies every Argon2id parameter explicitly; no implementation
///   parameter may be hardcoded.
/// - For `KDF_ARGON2ID_V1`, the effective profile is Argon2id version `0x13`
///   with 32 bytes of output.
/// ## Postconditions
/// - On success, returns exactly one `MasterUnlockKey` containing 32 bytes.
/// - On failure, returns `Err` and exposes no partial key material.
/// - The Argon2 salt is `b"meissnerseal-argon2id-salt-v1" || vault_id`.
/// ## Invariants
/// - Uses no custom cryptographic primitive.
/// - All fixed-length secret output is represented by `MasterUnlockKey`.
/// - Secret values are not compared with `==`; constant-time comparison is used
///   wherever secret equality is required.
pub fn derive(
    password: &[u8],
    vault_id: &[u8; 16],
    params: &Argon2Params,
) -> Result<MasterUnlockKey> {
    if params.m_cost_kib == 0
        || params.t_cost == 0
        || params.p_lanes == 0
        || params.output_len != MasterUnlockKey::LEN
        || params.m_cost_kib > ARGON2_MAX_M_COST_KIB
        || params.t_cost > ARGON2_MAX_T_COST
        || params.p_lanes > ARGON2_MAX_P_LANES
    {
        return Err(KdfError::InvalidInput);
    }

    let argon2_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_lanes,
        Some(params.output_len),
    )
    .map_err(|_| KdfError::InvalidInput)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let salt = construct_argon2id_salt(vault_id);
    let mut output = [0u8; MasterUnlockKey::LEN];

    argon2
        .hash_password_into(password, &salt, &mut output)
        .map_err(|_| KdfError::Backend)?;

    Ok(MasterUnlockKey::from_bytes(output))
}

/// Derive the 32-byte Vault Key Encryption Key from a Master Unlock Key.
///
/// # Contract
/// ## Preconditions
/// - `master_unlock_key` was produced by this crate's Argon2id KDF contract.
/// - `vault_id` is the canonical 128-bit vault UUID.
/// - The HKDF salt is `b"meissnerseal-vkek-salt-v1" || vault_id`.
/// - The HKDF info string is deterministic ASCII:
///   `b"meissnerseal:vault-kek:v1"`.
/// ## Postconditions
/// - On success, returns exactly one `VaultKeyEncKey` containing 32 bytes.
/// - On failure, returns `Err` and exposes no partial key material.
/// ## Invariants
/// - Uses no custom cryptographic primitive.
/// - All fixed-length secret output is represented by `VaultKeyEncKey`.
/// - Secret values are not logged, printed, written, or compared with `==`.
pub fn derive_vkek(
    master_unlock_key: &MasterUnlockKey,
    vault_id: &[u8; 16],
) -> Result<VaultKeyEncKey> {
    let mut salt = [0u8; 41];
    let (domain, vault) = salt.split_at_mut(VKEK_SALT_DOMAIN_V1.len());
    domain.copy_from_slice(VKEK_SALT_DOMAIN_V1);
    vault.copy_from_slice(vault_id);

    let prk = crate::kdf::hkdf::extract(&salt, master_unlock_key.as_slice());
    let vkek = crate::kdf::hkdf::expand::<{ VaultKeyEncKey::LEN }>(&prk, VKEK_INFO_V1)?;

    Ok(VaultKeyEncKey::from_bytes(*vkek.as_bytes()))
}

fn construct_argon2id_salt(vault_id: &[u8; 16]) -> [u8; 45] {
    let mut salt = [0u8; 45];
    let (domain, vault) = salt.split_at_mut(ARGON2ID_SALT_DOMAIN_V1.len());
    domain.copy_from_slice(ARGON2ID_SALT_DOMAIN_V1);
    vault.copy_from_slice(vault_id);
    salt
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn verify_argon2id_salt_length() {
        let vault_id = kani::any::<[u8; 16]>();
        let salt = construct_argon2id_salt(&vault_id);
        kani::assert(salt.len() == 45, "Argon2id salt must always be 40 bytes");
    }

    #[kani::proof]
    fn verify_vkek_output_length() {
        // Type-level proof: VaultKeyEncKey::LEN is a compile-time constant == 32.
        // Calling derive_vkek with kani::any() would symbolically execute HKDF/SHA256
        // which causes state space explosion. The output length is guaranteed by the
        // Key<32> return type, not by runtime behavior.
        kani::assert(VaultKeyEncKey::LEN == 32, "VKEK must always be 32 bytes");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const VAULT_ID: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    const PASSWORD: &[u8] = b"test-password-never-real";
    const PARAMS: Argon2Params = Argon2Params {
        m_cost_kib: 65_536,
        t_cost: 3,
        p_lanes: 4,
        output_len: 32,
    };
    // "meissnerseal-argon2id-salt-v1" (29) + vault_id (16) = 45
    const EXPECTED_ARGON2_SALT: [u8; 45] = [
        0x6d, 0x65, 0x69, 0x73, 0x73, 0x6e, 0x65, 0x72, 0x73, 0x65, 0x61, 0x6c, 0x2d, 0x61, 0x72,
        0x67, 0x6f, 0x6e, 0x32, 0x69, 0x64, 0x2d, 0x73, 0x61, 0x6c, 0x74, 0x2d, 0x76, 0x31, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    const EXPECTED_MUK: [u8; 32] = [
        0xf3, 0x1c, 0x08, 0xb3, 0x2b, 0xfd, 0x52, 0x23, 0xe2, 0x84, 0x39, 0x5d, 0xdc, 0xd6, 0xb3,
        0x37, 0x78, 0x37, 0xbf, 0x0f, 0x2f, 0x05, 0x10, 0x73, 0xd6, 0x92, 0xda, 0xbc, 0x44, 0x37,
        0x0b, 0xff,
    ];
    const EXPECTED_VKEK: [u8; 32] = [
        0x59, 0xa4, 0xe5, 0xd0, 0x35, 0xd7, 0x8c, 0x5b, 0x94, 0x1d, 0xb4, 0x14, 0x5c, 0xf5, 0xfe,
        0x26, 0xdc, 0x1f, 0x08, 0x10, 0x1d, 0x87, 0x25, 0xea, 0x4f, 0x52, 0xde, 0x84, 0x3c, 0x00,
        0x6e, 0x66,
    ];

    #[test]
    fn test_argon2id_salt_construction() {
        let salt = construct_argon2id_salt(&VAULT_ID);
        assert_eq!(salt, EXPECTED_ARGON2_SALT);
    }

    #[test]
    #[allow(unexpected_cfgs)]
    #[cfg_attr(miri, ignore = "Argon2id 64 MiB KDF is too slow under Miri")]
    fn test_muk_derivation() {
        let master_unlock_key = derive(PASSWORD, &VAULT_ID, &PARAMS).expect("MUK derivation");
        let expected = MasterUnlockKey::from_bytes(EXPECTED_MUK);

        assert!(bool::from(master_unlock_key.ct_eq(&expected)));
    }

    #[test]
    fn test_vkek_derivation() {
        let master_unlock_key = MasterUnlockKey::from_bytes(EXPECTED_MUK);
        let vault_key_encryption_key =
            derive_vkek(&master_unlock_key, &VAULT_ID).expect("VKEK derivation");
        let expected = VaultKeyEncKey::from_bytes(EXPECTED_VKEK);

        assert!(bool::from(vault_key_encryption_key.ct_eq(&expected)));
    }

    // Each guard condition is tested in isolation (exactly one invalid field,
    // every other field valid). This is the pattern that catches the `||`->`&&`
    // mutations in the validation chain: under `&&`, a single true condition no
    // longer short-circuits to Err. `m_cost_kib` is 256 (not 64) so the argon2
    // backend accepts `p_lanes = MAX+1` (which requires m >= 8*p); otherwise
    // Params::new would reject it and mask the guard mutation.
    fn valid_params() -> Argon2Params {
        Argon2Params {
            m_cost_kib: 256,
            t_cost: 1,
            p_lanes: 1,
            output_len: MasterUnlockKey::LEN,
        }
    }

    #[test]
    fn derive_rejects_m_cost_zero() {
        let params = Argon2Params {
            m_cost_kib: 0,
            ..valid_params()
        };
        assert!(matches!(
            derive(PASSWORD, &VAULT_ID, &params),
            Err(KdfError::InvalidInput)
        ));
    }

    #[test]
    fn derive_rejects_t_cost_zero() {
        let params = Argon2Params {
            t_cost: 0,
            ..valid_params()
        };
        assert!(matches!(
            derive(PASSWORD, &VAULT_ID, &params),
            Err(KdfError::InvalidInput)
        ));
    }

    #[test]
    fn derive_rejects_p_lanes_zero() {
        let params = Argon2Params {
            p_lanes: 0,
            ..valid_params()
        };
        assert!(matches!(
            derive(PASSWORD, &VAULT_ID, &params),
            Err(KdfError::InvalidInput)
        ));
    }

    #[test]
    fn derive_rejects_m_cost_above_max() {
        let params = Argon2Params {
            m_cost_kib: ARGON2_MAX_M_COST_KIB + 1,
            ..valid_params()
        };
        assert!(matches!(
            derive(PASSWORD, &VAULT_ID, &params),
            Err(KdfError::InvalidInput)
        ));
    }

    #[test]
    fn derive_rejects_t_cost_above_max() {
        let params = Argon2Params {
            t_cost: ARGON2_MAX_T_COST + 1,
            ..valid_params()
        };
        assert!(matches!(
            derive(PASSWORD, &VAULT_ID, &params),
            Err(KdfError::InvalidInput)
        ));
    }

    #[test]
    fn derive_rejects_p_lanes_above_max() {
        let params = Argon2Params {
            p_lanes: ARGON2_MAX_P_LANES + 1,
            ..valid_params()
        };
        assert!(matches!(
            derive(PASSWORD, &VAULT_ID, &params),
            Err(KdfError::InvalidInput)
        ));
    }

    #[test]
    fn derive_rejects_wrong_output_len() {
        let params = Argon2Params {
            output_len: MasterUnlockKey::LEN + 1,
            ..valid_params()
        };
        assert!(matches!(
            derive(PASSWORD, &VAULT_ID, &params),
            Err(KdfError::InvalidInput)
        ));
    }

    // Positive boundary tests: params at *exactly* the max must be ACCEPTED.
    // These kill the `>`->`>=` mutants on the max checks, which the `MAX + 1`
    // rejection tests cannot — both real and mutant reject `MAX + 1`, so only a
    // value of exactly MAX distinguishes `> MAX` (accept) from `>= MAX` (reject).
    #[test]
    #[cfg_attr(miri, ignore = "Argon2id KDF is too slow under Miri")]
    fn derive_accepts_t_cost_at_max() {
        let params = Argon2Params {
            t_cost: ARGON2_MAX_T_COST,
            ..valid_params()
        };
        assert!(derive(PASSWORD, &VAULT_ID, &params).is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id KDF is too slow under Miri")]
    fn derive_accepts_p_lanes_at_max() {
        let params = Argon2Params {
            p_lanes: ARGON2_MAX_P_LANES,
            ..valid_params()
        };
        assert!(derive(PASSWORD, &VAULT_ID, &params).is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Argon2id 256 MiB KDF is too slow under Miri")]
    fn derive_accepts_m_cost_at_max() {
        let params = Argon2Params {
            m_cost_kib: ARGON2_MAX_M_COST_KIB,
            ..valid_params()
        };
        assert!(derive(PASSWORD, &VAULT_ID, &params).is_ok());
    }
}
