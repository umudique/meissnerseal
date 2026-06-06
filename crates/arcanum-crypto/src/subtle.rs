//! Constant-time comparison re-exports.
//!
//! Callers must never use `==` on secret values.
//! Use `ConstantTimeEq::ct_eq` from this module instead.

pub use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Constant-time equality comparison for byte slices.
pub fn ct_eq(a: &[u8], b: &[u8]) -> Choice {
    use subtle::ConstantTimeEq;
    a.ct_eq(b)
}
