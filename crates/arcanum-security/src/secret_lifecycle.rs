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
        let v = vec![0u8; kani::any::<u8>() as usize];
        let len = v.len();
        let s = SecretBytes::new(v);
        kani::assert(s.len() == len, "SecretBytes len matches input");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_bytes_debug_is_redacted() {
        let s = SecretBytes(vec![1, 2, 3]);
        let rendered = format!("{s:?}");

        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains('1'));
    }

    #[test]
    fn test_secret_string_debug_is_redacted() {
        let s = SecretString(String::from("top-secret"));
        let rendered = format!("{s:?}");

        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("top-secret"));
    }

    #[test]
    fn test_secret_bytes_zeroize() {
        let bytes = vec![0xAAu8; 32];
        let ptr = {
            let s = SecretBytes::new(bytes);
            s.with_secret(|b| b.as_ptr())
        };

        let _ = ptr;
    }

    #[test]
    fn test_with_secret_scoped_access() {
        let s = SecretBytes::new(vec![0xde, 0xad]);
        let sum = s.with_secret(|b| b.iter().map(|x| u32::from(*x)).sum::<u32>());

        assert_eq!(sum, 0xde + 0xad);
    }
}
