#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

mod arithmetic;
mod constant_time;
pub use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
mod array;
#[cfg(feature = "alloc")]
mod big_int;
#[cfg(feature = "alloc")]
mod big_uint;
mod encoding;
mod error;
mod fixed_big_int;
mod fixed_big_uint;
mod format;
#[cfg(test)]
#[path = "limb_tests.rs"]
mod limb;
pub mod modular;
mod non_zero;
mod odd;
#[cfg(feature = "rand_core")]
mod prime;
mod traits;
mod types;

pub use array::ArrayEncoding;
#[cfg(feature = "alloc")]
pub use big_int::BigInt;
#[cfg(feature = "alloc")]
pub use big_uint::BigUint;
#[cfg(feature = "rand_core")]
pub use error::RandomBitsError;
pub use error::{ConversionError, ParseBigIntError};
pub use fixed_big_int::FixedBigInt;
pub use fixed_big_uint::FixedBigUint;
pub use tc_limb::{Limb, WideWord, Word};
use tc_limb::LimbArray;
pub use non_zero::NonZero;
pub use odd::Odd;
#[cfg(feature = "rand_core")]
pub use rand_core;
pub use traits::{
    AndNot, BitOps, Bounded, CheckedAdd, CheckedDiv, CheckedMul, CheckedNeg, CheckedRem,
    CheckedShl, CheckedShr, CheckedSub, DivRem, FromPrimitive, Gcd, ModAdd, ModInverse, ModMul,
    ModPow, ModSub, Num, NumAssign, NumAssignOps, NumAssignRef, NumOps, NumRef, One,
    OverflowingAdd, OverflowingMul, OverflowingSub, Pow, RefNum, RemEuclid, SaturatingAdd,
    SaturatingMul, SaturatingSub, Signed, Square, ToPrimitive, Unsigned, WrappingAdd, WrappingMul,
    WrappingNeg, WrappingSub, Zero,
};
#[cfg(feature = "rand_core")]
pub use traits::{
    IsProbablePrime, NextProbablePrime, ProbablePrime, Random, RandomBits, RandomMod,
};
pub use types::{I64, I128, I1024, U64, U128, U256, U384, U521, U1024, U2048};
