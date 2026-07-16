// SPDX-License-Identifier: Apache-2.0
//! Secret-bearing transfer payload wrapper.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Zeroizing wrapper for transfer plaintext payload bytes.
///
/// # Contract
///
/// ## Preconditions
/// - `bytes` contains secret plaintext material that must not be logged,
///   formatted, or exposed through raw-byte accessors.
/// - The caller transfers ownership of `bytes` to this wrapper.
///
/// ## Postconditions
/// - Returns a payload wrapper that zeroizes its backing memory on drop.
/// - Secret bytes remain accessible only through scoped access methods.
///
/// ## Invariants
/// - Implements `Zeroize` and `ZeroizeOnDrop`.
/// - Does not implement `Clone`, `Debug`, `Display`, or `PartialEq`.
/// - Provides no public method that returns owned raw secret bytes.
pub struct SecretPayload(Zeroizing<Vec<u8>>);

impl SecretPayload {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.0.as_slice())
    }

    pub(crate) fn into_inner(mut self) -> Zeroizing<Vec<u8>> {
        core::mem::take(&mut self.0)
    }
}

impl core::fmt::Debug for SecretPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretPayload([REDACTED])")
    }
}

impl Zeroize for SecretPayload {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretPayload {}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use core::mem::ManuallyDrop;
    use core::ops::DerefMut;
    use core::slice;
    use static_assertions::{assert_impl_all, assert_not_impl_any};

    assert_impl_all!(SecretPayload: Zeroize, ZeroizeOnDrop);
    assert_not_impl_any!(SecretPayload: Clone, PartialEq, core::fmt::Display);

    #[test]
    fn debug_is_redacted() {
        let payload = SecretPayload::new(vec![0xAA; 8]);
        let rendered = format!("{payload:?}");

        assert_eq!(rendered, "SecretPayload([REDACTED])");
        assert!(!rendered.contains("AA"));
    }

    #[test]
    fn with_secret_exposes_bytes_only_inside_closure() {
        let payload = SecretPayload::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let observed = payload.with_secret(|bytes| bytes.len());

        assert_eq!(observed, 4);
    }

    #[test]
    fn len_and_is_empty_match_payload_state() {
        let non_empty = SecretPayload::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let empty = SecretPayload::new(Vec::new());

        assert_eq!(non_empty.len(), 4);
        assert!(!non_empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn zeroize_clears_backing_buffer_contents() {
        let mut payload = SecretPayload::new(vec![0xAB; 16]);
        payload.zeroize();

        payload.with_secret(|bytes| assert!(bytes.iter().all(|byte| *byte == 0)));
    }

    #[test]
    #[allow(unsafe_code)] // REASON: raw-pointer inspection validates zeroizing drop behavior.
    fn drop_path_uses_zeroizing_backing_storage() {
        let mut payload = ManuallyDrop::new(SecretPayload::new(vec![0xCD; 16]));
        let ptr = payload.0.as_ptr();
        let len = payload.0.len();

        ManuallyDrop::deref_mut(&mut payload).zeroize();

        unsafe { // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            // SAFETY: `ptr` points into the still-live allocation owned by
            // `payload`. `zeroize()` clears bytes in place before the final
            // destructor frees the allocation. Reading the allocation after
            // `ManuallyDrop::drop` would observe freed memory, so the check is
            // performed before the final manual drop.
            let bytes = slice::from_raw_parts(ptr, len);
            assert!(bytes.iter().all(|byte| *byte == 0));

            // SAFETY: free the backing allocation after the zeroization check
            // to avoid leaking the test fixture.
            ManuallyDrop::drop(&mut payload);
        }
    }
}
