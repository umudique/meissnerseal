use zeroize::{Zeroize, ZeroizeOnDrop};

/// A fixed-length cryptographic key, nonce, or identifier.
///
/// The length `N` is a compile-time constant encoded in the type.
/// The compiler verifies that every assignment matches the expected length.
///
/// # Security guarantees
///
/// - Memory is zeroized on drop (ZeroizeOnDrop)
/// - Debug output is always redacted ([REDACTED])
/// - PartialEq is intentionally not implemented.
///   Use `subtle::ConstantTimeEq` for constant-time comparison.
///
/// # Examples
///
/// ```ignore
/// let key = AeadKey::from_bytes([0u8; 32]);
/// let nonce = XChaCha20Nonce::from_bytes([0u8; 24]);
/// // key == nonce  <-- compile error: different types
/// // key == key    <-- compile error: PartialEq not implemented
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key<const N: usize>([u8; N]);

impl<const N: usize> Key<N> {
    /// The byte length of this key type. Available at compile time.
    pub const LEN: usize = N;

    /// Construct from a fixed-size byte array.
    /// The size is verified at compile time.
    #[inline]
    pub fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Access the raw bytes as a fixed-size array reference.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Access the raw bytes as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Constant-time equality comparison.
    /// This is the ONLY correct way to compare Key values.
    /// Never use == for secret comparison.
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0)
    }
}

/// Redacted debug output. Secret bytes are never logged.
impl<const N: usize> core::fmt::Debug for Key<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Key<{}>([REDACTED])", N)
    }
}

// ── Type aliases — fixed-length cryptographic types ──────────────────────────

/// 32-byte AEAD encryption key (XChaCha20-Poly1305 or AES-256-GCM)
pub type AeadKey = Key<32>;

/// 24-byte XChaCha20-Poly1305 nonce (192-bit)
pub type XChaCha20Nonce = Key<24>;

/// 12-byte AES-256-GCM nonce (96-bit, strict optional profile only)
pub type AesGcmNonce = Key<12>;

/// 16-byte vault UUID identifier
pub type VaultId = Key<16>;

/// 16-byte random record identifier
pub type RecordId = Key<16>;

/// 16-byte random revision identifier
pub type RevisionId = Key<16>;

/// 24-byte random vault header nonce
pub type HeaderNonce = Key<24>;

/// 32-byte Master Unlock Key — output of KDF_ARGON2ID_V1
pub type MasterUnlockKey = Key<32>;

/// 32-byte Vault Key Encryption Key — HKDF-derived from MUK
pub type VaultKeyEncKey = Key<32>;

/// 32-byte Vault Root Key
pub type VaultRootKey = Key<32>;

/// 32-byte HKDF pseudo-random key (output of HKDF-Extract)
pub type HkdfPrk = Key<32>;

/// 32-byte HKDF-derived subkey (output of HKDF-Expand)
pub type DerivedSubkey = Key<32>;

/// 32-byte Record Encryption Key — fresh per revision, OS CSPRNG
pub type RecordEncKey = Key<32>;

/// 32-byte transfer payload key — derived from hybrid X25519+ML-KEM
pub type TransferPayloadKey = Key<32>;

// ── Kani proof harnesses ─────────────────────────────────────────────────────
// These harnesses run only under `cargo kani`. They do not affect the
// production binary. Each harness proves a bounded property.

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Prove: AeadKey is always exactly 32 bytes.
    #[kani::proof]
    fn verify_aead_key_length() {
        let k = AeadKey::from_bytes(kani::any::<[u8; 32]>());
        kani::assert(k.as_slice().len() == 32, "AeadKey must be 32 bytes");
        kani::assert(AeadKey::LEN == 32, "AeadKey::LEN must be 32");
    }

    /// Prove: XChaCha20Nonce is always exactly 24 bytes.
    #[kani::proof]
    fn verify_xchacha20_nonce_length() {
        let n = XChaCha20Nonce::from_bytes(kani::any::<[u8; 24]>());
        kani::assert(n.as_slice().len() == 24, "XChaCha20Nonce must be 24 bytes");
    }

    /// Prove: AesGcmNonce is always exactly 12 bytes.
    #[kani::proof]
    fn verify_aesgcm_nonce_length() {
        let n = AesGcmNonce::from_bytes(kani::any::<[u8; 12]>());
        kani::assert(n.as_slice().len() == 12, "AesGcmNonce must be 12 bytes");
    }

    /// Prove: VaultId, RecordId, RevisionId are all exactly 16 bytes.
    #[kani::proof]
    fn verify_id_lengths() {
        let v = VaultId::from_bytes(kani::any::<[u8; 16]>());
        let r = RecordId::from_bytes(kani::any::<[u8; 16]>());
        let rv = RevisionId::from_bytes(kani::any::<[u8; 16]>());
        kani::assert(v.as_slice().len() == 16, "VaultId must be 16 bytes");
        kani::assert(r.as_slice().len() == 16, "RecordId must be 16 bytes");
        kani::assert(rv.as_slice().len() == 16, "RevisionId must be 16 bytes");
    }

    /// Prove: Key<N>::LEN equals N for representative sizes.
    #[kani::proof]
    fn verify_const_len() {
        kani::assert(Key::<16>::LEN == 16, "Key<16>::LEN");
        kani::assert(Key::<24>::LEN == 24, "Key<24>::LEN");
        kani::assert(Key::<32>::LEN == 32, "Key<32>::LEN");
    }

    /// Prove: Key zeroize does not panic (structural soundness).
    #[kani::proof]
    fn verify_zeroize_does_not_panic() {
        let mut k = AeadKey::from_bytes(kani::any::<[u8; 32]>());
        k.zeroize();
        // If we reach here, no panic occurred
    }

    // TODO (MVP-0): add proofs for argon2 salt construction length
    // TODO (MVP-0): add proofs for AAD v1 construction (74 bytes)
    // TODO (MVP-0): add proofs for HKDF info string encoding
    // TODO (MVP-2): add proofs for transcript hash binding length
}

// ── Unit tests ───────────────────────────────────────────────────────────────
// These run under `cargo test`. The Kani harnesses above prove the same
// properties for ALL inputs; these confirm concrete behavior and runtime API.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const_len_matches_type() {
        assert_eq!(AeadKey::LEN, 32);
        assert_eq!(XChaCha20Nonce::LEN, 24);
        assert_eq!(AesGcmNonce::LEN, 12);
        assert_eq!(VaultId::LEN, 16);
    }

    #[test]
    fn slice_length_matches_const() {
        let k = AeadKey::from_bytes([7u8; 32]);
        assert_eq!(k.as_slice().len(), 32);
        assert_eq!(k.as_bytes().len(), 32);
    }

    #[test]
    fn ct_eq_true_for_equal_keys() {
        let a = AeadKey::from_bytes([1u8; 32]);
        let b = AeadKey::from_bytes([1u8; 32]);
        assert!(bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn ct_eq_false_for_different_keys() {
        let a = AeadKey::from_bytes([1u8; 32]);
        let mut other = [1u8; 32];
        other[31] = 0;
        let b = AeadKey::from_bytes(other);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn debug_output_is_redacted() {
        let k = AeadKey::from_bytes([0xABu8; 32]);
        let rendered = format!("{k:?}");
        assert!(rendered.contains("REDACTED"));
        // No raw secret byte appears in the debug output
        assert!(!rendered.contains("ab"));
        assert!(!rendered.contains("171"));
    }
}
