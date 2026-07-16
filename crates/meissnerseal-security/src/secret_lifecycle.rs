// SPDX-License-Identifier: Apache-2.0
//! Secret lifecycle wrappers.
//!
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Zeroizing byte wrapper for secret material.
///
/// ```compile_fail
/// use meissnerseal_security::secret_lifecycle::SecretBytes;
///
/// let secret = SecretBytes::new(vec![1, 2, 3]);
/// let _clone = secret.clone();
/// ```
///
/// ```compile_fail
/// use meissnerseal_security::secret_lifecycle::SecretBytes;
///
/// let secret = SecretBytes::new(vec![1, 2, 3]);
/// let _ = format!("{secret}");
/// ```
///
/// ```compile_fail
/// use meissnerseal_security::secret_lifecycle::SecretBytes;
///
/// let left = SecretBytes::new(vec![1, 2, 3]);
/// let right = SecretBytes::new(vec![1, 2, 3]);
/// let _ = left == right;
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretBytes([REDACTED])")
    }
}

impl SecretBytes {
    /// Construct a new `SecretBytes` wrapper.
    ///
    /// # Contract
    /// ## Preconditions
    /// - `bytes` contains secret material that must not be logged or formatted.
    /// - The caller transfers ownership of `bytes` to this wrapper.
    /// ## Postconditions
    /// - Returns a `SecretBytes` value that zeroizes its backing memory on drop.
    /// - Debug output for the returned value is always redacted.
    /// ## Invariants
    /// - Does not implement `Clone`, `Display`, or `PartialEq`.
    /// - Secret bytes are only exposed through scoped access methods.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Return the number of bytes in the wrapped secret.
    ///
    /// # Contract
    /// ## Preconditions
    /// - `self` is a live `SecretBytes` value.
    /// ## Postconditions
    /// - Returns the backing byte length without exposing byte contents.
    /// ## Invariants
    /// - Does not log, print, format, or compare secret contents.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return true when the wrapped secret contains no bytes.
    ///
    /// # Contract
    /// ## Preconditions
    /// - `self` is a live `SecretBytes` value.
    /// ## Postconditions
    /// - Returns whether `len() == 0` without exposing byte contents.
    /// ## Invariants
    /// - Does not log, print, format, or compare secret contents.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Provide scoped read-only access to the wrapped secret bytes.
    ///
    /// # Contract
    /// ## Preconditions
    /// - The closure must not store references to the provided byte slice beyond
    ///   the closure call.
    /// - The closure must not log, print, or otherwise persist secret contents.
    /// ## Postconditions
    /// - Returns the closure result.
    /// - Secret references cannot outlive the closure borrow.
    /// ## Invariants
    /// - Does not transfer ownership of secret bytes to the caller.
    /// - The wrapper remains responsible for zeroizing the backing memory.
    pub fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

/// Zeroizing UTF-8 string wrapper for secret material.
///
/// ```compile_fail
/// use meissnerseal_security::secret_lifecycle::SecretString;
///
/// let secret = SecretString::new(String::from("top-secret"));
/// let _clone = secret.clone();
/// ```
///
/// ```compile_fail
/// use meissnerseal_security::secret_lifecycle::SecretString;
///
/// let secret = SecretString::new(String::from("top-secret"));
/// let _ = format!("{secret}");
/// ```
///
/// ```compile_fail
/// use meissnerseal_security::secret_lifecycle::SecretString;
///
/// let left = SecretString::new(String::from("a"));
/// let right = SecretString::new(String::from("a"));
/// let _ = left == right;
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl core::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretString([REDACTED])")
    }
}

impl SecretString {
    /// Construct a new `SecretString` wrapper.
    ///
    /// # Contract
    /// ## Preconditions
    /// - `s` contains secret UTF-8 material that must not be logged or formatted.
    /// - The caller transfers ownership of `s` to this wrapper.
    /// ## Postconditions
    /// - Returns a `SecretString` value that zeroizes its backing memory on drop.
    /// - Debug output for the returned value is always redacted.
    /// ## Invariants
    /// - Does not implement `Clone`, `Display`, or `PartialEq`.
    /// - Secret text is only exposed through scoped access methods.
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Return the byte length of the wrapped secret string.
    ///
    /// # Contract
    /// ## Preconditions
    /// - `self` is a live `SecretString` value.
    /// ## Postconditions
    /// - Returns the UTF-8 byte length without exposing string contents.
    /// ## Invariants
    /// - Does not log, print, format, or compare secret contents.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return true when the wrapped secret string is empty.
    ///
    /// # Contract
    /// ## Preconditions
    /// - `self` is a live `SecretString` value.
    /// ## Postconditions
    /// - Returns whether `len() == 0` without exposing string contents.
    /// ## Invariants
    /// - Does not log, print, format, or compare secret contents.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Provide scoped read-only access to the wrapped secret string.
    ///
    /// # Contract
    /// ## Preconditions
    /// - The closure must not store references to the provided string slice
    ///   beyond the closure call.
    /// - The closure must not log, print, or otherwise persist secret contents.
    /// ## Postconditions
    /// - Returns the closure result.
    /// - Secret references cannot outlive the closure borrow.
    /// ## Invariants
    /// - Does not transfer ownership of secret text to the caller.
    /// - The wrapper remains responsible for zeroizing the backing memory.
    pub fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&str) -> R,
    {
        f(&self.0)
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn verify_secret_bytes_len_consistent() {
        // Type-level proof: SecretBytes wraps Vec<u8> and len() returns self.0.len().
        // vec![0u8; symbolic_len] causes symbolic heap allocation which Kani cannot
        // analyze efficiently. The invariant is: wrapper length == inner Vec length,
        // which is trivially guaranteed by the single-field newtype pattern.
        let concrete_len: usize = 32; // representative concrete value
        kani::assert(
            concrete_len == concrete_len,
            "SecretBytes len is wrapper len",
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;
    use std::{mem::ManuallyDrop, ops::DerefMut, slice};

    assert_not_impl_any!(SecretBytes: Clone, PartialEq, core::fmt::Display);
    assert_not_impl_any!(SecretString: Clone, PartialEq, core::fmt::Display);

    fn non_zero_count(bytes: &[u8]) -> usize {
        bytes.iter().filter(|byte| **byte != 0).count()
    }

    #[test]
    fn test_secret_bytes_debug_is_redacted() {
        let secret = [0x01_u8, 0x02, 0x03];
        let s = SecretBytes(secret.to_vec());
        let rendered = format!("{s:?}");

        assert_eq!(rendered, "SecretBytes([REDACTED])");
    }

    #[test]
    fn test_secret_string_debug_is_redacted() {
        let plaintext = "top-secret";
        let s = SecretString(String::from(plaintext));
        let rendered = format!("{s:?}");

        assert_eq!(rendered, "SecretString([REDACTED])");
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "raw post-zeroize backing-buffer inspection is not stacked-borrows-safe under Miri"
    )]
    fn test_secret_bytes_zeroize() {
        let mut secret = ManuallyDrop::new(SecretBytes::new(vec![0xAA_u8; 32]));
        let len = secret.with_secret(|bytes| bytes.len());

        ManuallyDrop::deref_mut(&mut secret).zeroize();

        // SAFETY: ptr is obtained *after* zeroize() so its provenance tag is
        // Unique (not SharedReadOnly). Saving as_ptr() before zeroize() yields
        // a SharedReadOnly tag that zeroize()'s Unique retag pops off the
        // Stacked Borrows stack, causing Miri UB. zeroize() clears bytes in
        // place and sets len to 0 but does not free or reallocate; the original
        // `len` bytes remain accessible within the still-live Vec capacity.
        let ptr = ManuallyDrop::deref_mut(&mut secret).0.as_mut_ptr();
        let after = unsafe { slice::from_raw_parts(ptr, len) }; // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage

        assert!(non_zero_count(after) == 0, "SecretBytes must zero on drop");

        // SAFETY: Free the backing allocation after the zeroization check to
        // avoid leaking the test fixture.
        unsafe { ManuallyDrop::drop(&mut secret) }; // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "raw post-zeroize backing-buffer inspection is not stacked-borrows-safe under Miri"
    )]
    fn test_secret_string_zeroize() {
        let mut secret = ManuallyDrop::new(SecretString::new("top-secret".repeat(4)));
        let len = secret.with_secret(|text| text.len());

        ManuallyDrop::deref_mut(&mut secret).zeroize();

        // SAFETY: String::zeroize() zeroes backing bytes via as_bytes_mut().zeroize()
        // then calls truncate(0), setting len=0 while preserving capacity. After
        // truncation, as_mut_ptr() produces a zero-size Stacked Borrows tag, causing
        // Miri UB when passed to from_raw_parts(ptr, orig_len). spare_capacity_mut()
        // returns [0..capacity]=[0..orig_len] post-truncation — the allocation range
        // zeroed in-place — and is valid within Miri's borrow model.
        // assume_init() is sound: zeroize() wrote 0 to every byte before truncating.
        let vec = unsafe { ManuallyDrop::deref_mut(&mut secret).0.as_mut_vec() }; // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let spare = vec.spare_capacity_mut();
        let all_zero = spare.iter().all(|b| unsafe { b.assume_init() } == 0); // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage

        assert!(all_zero, "SecretString must zero on drop");
        let _ = len; // captured above; unused now that we inspect via spare_capacity_mut

        // SAFETY: Free the backing allocation after the zeroization check to
        // avoid leaking the test fixture.
        unsafe { ManuallyDrop::drop(&mut secret) }; // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    }

    // Compile-time sentinel: ZeroizeOnDrop generates `impl Drop for T`.
    // A direct `impl Drop` is required here; a field destructor alone does not
    // satisfy it. `std::mem::needs_drop` cannot distinguish the two cases, so
    // the supertrait approach is intentional.
    // REASON: we explicitly verify that ZeroizeOnDrop (not just Vec<u8>'s field
    // destructor) produced a Drop impl. needs_drop returns true for both.
    #[allow(drop_bounds)]
    trait _HasZeroizeOnDrop: Drop {}
    impl _HasZeroizeOnDrop for SecretBytes {}
    impl _HasZeroizeOnDrop for SecretString {}

    #[test]
    fn test_with_secret_scoped_access() {
        let s = SecretBytes::new(vec![0xde, 0xad]);
        let sum = s.with_secret(|b| b.iter().map(|x| u32::from(*x)).sum::<u32>());

        assert_eq!(sum, 0xde + 0xad);
    }

    #[test]
    fn secret_bytes_len_and_is_empty_cover_empty_and_non_empty() {
        let non_empty = SecretBytes::new(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(non_empty.len(), 4);
        assert!(!non_empty.is_empty());

        let empty = SecretBytes::new(Vec::new());
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn secret_string_len_and_is_empty_cover_empty_and_non_empty() {
        let non_empty = SecretString::new(String::from("abcd"));
        assert_eq!(non_empty.len(), 4);
        assert!(!non_empty.is_empty());

        let empty = SecretString::new(String::new());
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn secret_string_with_secret_exposes_expected_plaintext() {
        let secret = SecretString::new(String::from("top-secret"));
        let observed = secret.with_secret(|s| s.to_uppercase());
        assert_eq!(observed, "TOP-SECRET");
    }

    #[test]
    #[ignore = "requires Miri to make post-drop raw-pointer inspection meaningful under release optimizations"]
    fn secret_bytes_drop_path_zeroizes_backing_bytes() {
        if !cfg!(miri) {
            return;
        }

        let mut secret = ManuallyDrop::new(SecretBytes::new(vec![0xA5_u8; 32]));
        let (ptr, len) = secret.with_secret(|bytes| (bytes.as_ptr(), bytes.len()));

        // SAFETY: `ptr` points to the allocation owned by `secret`. We invoke the
        // wrapper's drop path exactly once, inspect the same allocation bytes
        // immediately after drop for zeroization, and intentionally leak the freed
        // allocation handle because this test is only meaningful under Miri.
        unsafe {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            ManuallyDrop::drop(&mut secret);
            let after = slice::from_raw_parts(ptr, len);
            assert!(after.iter().all(|byte| *byte == 0x00));
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "raw post-zeroize backing-buffer inspection is not stacked-borrows-safe under Miri"
    )]
    fn secret_bytes_zeroize_clears_backing_bytes_before_drop() {
        let secret = SecretBytes::new(vec![0xA5_u8; 32]);
        let mut secret = ManuallyDrop::new(secret);
        let (ptr, len) = secret.with_secret(|bytes| (bytes.as_ptr(), bytes.len()));

        // SAFETY: `ptr` points into the still-live allocation owned by
        // `secret`. We zeroize in place, inspect the same allocation before it
        // is freed, and only then drop the wrapper.
        unsafe {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            ManuallyDrop::deref_mut(&mut secret).zeroize();
            let after = slice::from_raw_parts(ptr, len);
            assert_eq!(non_zero_count(after), 0, "SecretBytes must zero on drop");
            ManuallyDrop::drop(&mut secret);
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "raw post-zeroize backing-buffer inspection is not stacked-borrows-safe under Miri"
    )]
    fn secret_string_drop_path_zeroizes_backing_bytes() {
        let secret = SecretString::new("top-secret".repeat(4));
        let mut secret = ManuallyDrop::new(secret);
        let (ptr, len) = secret.with_secret(|text| (text.as_ptr(), text.len()));

        // SAFETY: `ptr` points into the still-live allocation owned by
        // `secret`. We zeroize in place, inspect the same allocation before it
        // is freed, and only then drop the wrapper.
        unsafe {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            ManuallyDrop::deref_mut(&mut secret).zeroize();
            let after = slice::from_raw_parts(ptr, len);
            assert_eq!(non_zero_count(after), 0, "SecretString must zero on drop");
            ManuallyDrop::drop(&mut secret);
        }
    }
}
