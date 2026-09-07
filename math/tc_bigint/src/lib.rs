#![no_std]
//! Four little-endian big-integer types, in two pairs.
//!
//! [`BigUint`] and [`BigInt`] grow as needed and require the default `alloc`
//! feature. [`FixedBigUint<N>`] and [`FixedBigInt<N>`] hold exactly `N` limbs;
//! their arithmetic and caller-buffer encodings never allocate, so they remain
//! available with `default-features = false`.
//!
//! # Widths
//!
//! Name the fixed-width types through the bit-width aliases rather than a limb
//! count: limb width follows the target and is not part of the public API.
//!
//! ```
//! use tc_bigint::{U256, U2048};
//! assert_eq!(size_of::<U256>() * 8, 256);
//! assert_eq!(size_of::<U2048>() * 8, 2048);
//! ```
//!
//! # Representation
//!
//! Signed values use two's complement. Conversions name their byte order, so
//! callers choose it explicitly instead of inheriting an internal layout.
//!
//! ```
//! use tc_bigint::{ArrayEncoding, U64};
//! let value = U64::from_be_bytes(&[0x01, 0x02]).unwrap();
//! assert_eq!(value.to_be_bytes(), [0, 0, 0, 0, 0, 0, 0x01, 0x02]);
//! assert_eq!(value.to_le_bytes(), [0x02, 0x01, 0, 0, 0, 0, 0, 0]);
//! ```
//!
//! # Traits
//!
//! The numeric traits are defined here rather than taken from `num-traits`,
//! and are not type-compatible with `num_traits::*`. They are grouped by role:
//! identities and bound aggregators, big-integer operations, overflow
//! policies, primitive conversion, slice conversion, and randomised
//! construction. The crate README lists which of the four types implements
//! each one.
//!
//! # Features
//!
//! `alloc` and `rand_core` are on by default. Use
//! `default-features = false, features = ["rand_core"]` for fixed-width random
//! and prime operations without an allocator, or disable both for fixed-width
//! arithmetic only.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

pub use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
#[cfg(feature = "alloc")]
mod big_int;
#[cfg(feature = "alloc")]
mod big_uint;
mod encoding;
mod error;
mod fixed_big_int;
mod fixed_big_uint;
mod format;
mod limb;
pub mod modular;
mod non_zero;
mod odd;
mod ops_forward;
#[cfg(feature = "rand_core")]
mod prime;
mod traits;
mod types;

#[cfg(feature = "alloc")]
pub use big_int::BigInt;
#[cfg(feature = "alloc")]
pub use big_uint::BigUint;
#[cfg(feature = "rand_core")]
pub use error::RandomBitsError;
pub use error::{ConversionError, ParseBigIntError};
pub use fixed_big_int::FixedBigInt;
pub use fixed_big_uint::FixedBigUint;
pub(crate) use limb::array::LimbArray;
pub(crate) use limb::{Limb, WideWord, Word};
pub use non_zero::NonZero;
pub use odd::Odd;
#[cfg(feature = "rand_core")]
pub use rand_core;
#[cfg(feature = "alloc")]
pub use traits::ToStrRadix;
pub use traits::{
    AndNot, ArrayEncoding, BitOps, Bounded, CheckedAdd, CheckedDiv, CheckedMul, CheckedNeg,
    CheckedRem, CheckedShl, CheckedShr, CheckedSub, DivRem, FromPrimitive, Gcd, ModAdd, ModInverse,
    ModMul, ModPow, ModSub, Num, NumAssign, NumAssignOps, NumAssignRef, NumOps, NumRef, One,
    OverflowingAdd, OverflowingMul, OverflowingSub, Pow, RefNum, RemEuclid, SaturatingAdd,
    SaturatingMul, SaturatingSub, Signed, Square, ToPrimitive, Unsigned, WrappingAdd, WrappingMul,
    WrappingNeg, WrappingSub, Zero,
};
#[cfg(feature = "rand_core")]
pub use traits::{
    IsProbablePrime, NextProbablePrime, ProbablePrime, Random, RandomBits, RandomMod,
};
pub use types::{
    I64, I128, I1024, U64, U128, U256, U384, U512, U521, U1024, U1536, U2048, U3072, U4096,
};
