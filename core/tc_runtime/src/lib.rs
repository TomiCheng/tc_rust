//! Low-level runtime support for the `tc_rust` workspace.
//!
//! ```
//! use tc_runtime::intrinsics::x86::{AesNi, Sse2};
//!
//! assert_eq!(Sse2::detect().is_some(), Sse2::is_enabled());
//! assert_eq!(AesNi::detect().is_some(), AesNi::is_enabled());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

pub mod intrinsics;
