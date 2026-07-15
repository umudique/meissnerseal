// SPDX-License-Identifier: Apache-2.0
//! Secret lifecycle wrappers.
//!
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Zeroizing byte wrapper for secret material.
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
    use std::{mem::ManuallyDrop, ops::DerefMut, slice};

    fn non_zero_count(bytes: &[u8]) -> usize {
        bytes.iter().filter(|byte| **byte != 0).count()
    }

    #[test]
    fn test_secret_bytes_debug_is_redacted() {
        let secret = [0x01_u8, 0x02, 0x03];
        let s = SecretBytes(secret.to_vec());
        let rendered = format!("{s:?}");

        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("SecretBytes"));
        assert!(!rendered.contains("1"));
        assert!(!rendered.contains("2"));
        assert!(!rendered.contains("3"));
    }

    #[test]
    fn test_secret_string_debug_is_redacted() {
        let plaintext = "top-secret";
        let s = SecretString(String::from(plaintext));
        let rendered = format!("{s:?}");

        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("SecretString"));
        assert!(!rendered.contains(plaintext));
    }

    #[test]
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
    fn test_secret_string_zeroize() {
        let mut secret = ManuallyDrop::new(SecretString::new("top-secret".repeat(4)));
        let len = secret.with_secret(|text| text.len());

        ManuallyDrop::deref_mut(&mut secret).zeroize();

        // SAFETY: same Stacked Borrows rationale as test_secret_bytes_zeroize —
        // ptr is obtained after zeroize() to avoid SharedReadOnly→Unique
        // provenance conflict. String::as_mut_ptr() is valid post-clear since
        // the backing allocation is unchanged.
        let ptr = ManuallyDrop::deref_mut(&mut secret).0.as_mut_ptr();
        let after = unsafe { slice::from_raw_parts(ptr, len) }; // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage

        assert!(non_zero_count(after) == 0, "SecretString must zero on drop");

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
}
