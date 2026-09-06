#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
//!
//! ## 編譯期邊界
//!
//! 長度不相同會在編譯期被拒絕：
//! ```compile_fail
//! use tc_limb::LimbArray;
//! let _ = LimbArray::<1>::zero().add(&LimbArray::<2>::zero());
//! ```
//!
//! 呼叫端無法直接存取任一型別的內部欄位：
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
