//! Signed arbitrary-precision integer arithmetic.
//!
//! See the crate [`README`](https://github.com/TomiCheng/tc_rust/tree/develop/math/tc_bigint)
//! for usage, runtime requirements, and security limitations.

#![cfg_attr(not(feature = "std"), no_std)]

// Arbitrary-precision values require owned, dynamically sized storage, but do
// not require the standard library.
extern crate alloc;

mod big_integer;

pub use big_integer::{BigInteger, BufferTooSmall, ParseBigIntegerError, TryFromBigIntegerError};
