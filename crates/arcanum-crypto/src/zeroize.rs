// SPDX-License-Identifier: Apache-2.0
//! Secret memory zeroization re-exports.
//!
//! All types holding secret material must implement Zeroize + ZeroizeOnDrop.

pub use zeroize::{Zeroize, ZeroizeOnDrop};
