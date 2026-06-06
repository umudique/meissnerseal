//! Secret memory zeroization re-exports.
//!
//! All types holding secret material must implement Zeroize + ZeroizeOnDrop.

pub use zeroize::{Zeroize, ZeroizeOnDrop};
