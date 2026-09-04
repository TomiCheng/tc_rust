#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

mod arithmetic;
mod array;
#[cfg(feature = "alloc")]
mod big_int;
#[cfg(feature = "alloc")]
mod big_uint;
mod encoding;
mod error;
mod fixed_big_int;
mod fixed_big_uint;
mod limb;
mod non_zero;
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
pub use limb::{Limb, WideWord, Word};
pub use non_zero::NonZero;
#[cfg(feature = "rand_core")]
pub use rand_core;
pub use traits::{
    AndNot, BitOps, CheckedAdd, CheckedSub, DivRem, FromPrimitive, Gcd, ModInverse, ModPow, Num,
    NumAssign, NumAssignOps, NumAssignRef, NumOps, NumRef, One, OverflowingAdd, Pow, RefNum,
    RemEuclid, SaturatingAdd, Signed, Square, ToPrimitive, Unsigned, WrappingAdd, Zero,
};
#[cfg(feature = "rand_core")]
pub use traits::{
    IsProbablePrime, NextProbablePrime, ProbablePrime, Random, RandomBits, RandomMod,
};
pub use types::{I64, I128, I1024, U64, U128, U1024, U2048};
