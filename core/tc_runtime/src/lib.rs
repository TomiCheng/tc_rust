//! Low-level runtime support for the `tc_rust` workspace.
//!
//! ```
//! use tc_runtime::intrinsics::x86::{Aes, Avx2, Sse2};
//!
//! assert_eq!(Sse2::detect().is_some(), Sse2::is_enabled());
//! assert_eq!(Aes::detect().is_some(), Aes::is_enabled());
//! assert_eq!(Avx2::detect().is_some(), Avx2::is_enabled());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

pub mod intrinsics;
