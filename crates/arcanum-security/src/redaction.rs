//! Redaction helpers.

/// Generate a redacted `Debug` implementation for a type.
///
/// # Contract
/// ## Preconditions
/// - The target type contains secret or sensitive material that must never be
///   exposed through formatting.
/// - The target type does not already implement `core::fmt::Debug`.
/// ## Postconditions
/// - `Debug` output for the target type is always `[REDACTED]`.
/// - No field values are inspected or formatted.
/// ## Invariants
/// - The generated implementation does not log, print, or write secret values.
/// - The generated implementation is deterministic and content-independent.
#[allow(unused_macros)]
macro_rules! redacted_debug {
    ($t:ty) => {
        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($t), "([REDACTED])"))
            }
        }
    };
}

#[allow(unused_imports)]
pub(crate) use redacted_debug;
