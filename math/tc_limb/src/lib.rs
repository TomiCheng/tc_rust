#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
//!
//! ## Compile-time boundaries
//!
//! Mismatched lengths are rejected at compile time:
//! ```compile_fail
//! use tc_limb::LimbArray;
//! let _ = LimbArray::<1>::zero().add(&LimbArray::<2>::zero());
//! ```
//!
//! Callers cannot directly access the internal fields of either type:
//! ```compile_fail
//! use tc_limb::Limb;
//! let _ = Limb::new(1).0;
//! ```
//! ```compile_fail
//! use tc_limb::LimbArray;
//! let _ = LimbArray::<1>::zero().0;
//! ```

mod limb;
mod limb_array;

pub use limb::{Limb, WideWord, Word};
pub use limb_array::LimbArray;
pub use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
