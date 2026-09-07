//! Local numeric trait contracts.
//!
//! These interfaces are adapted from `num-traits` 0.2 and intentionally live
//! in this crate. No `num-traits` dependency is required, and these are distinct
//! Rust traits rather than drop-in implementations of `num_traits::*`.

mod array;
mod checked;
mod convert;
mod numeric;
mod ops;
#[cfg(feature = "rand_core")]
mod random;

pub use array::ArrayEncoding;
pub use checked::{
    CheckedAdd, CheckedDiv, CheckedMul, CheckedNeg, CheckedRem, CheckedShl, CheckedShr, CheckedSub,
    OverflowingAdd, OverflowingMul, OverflowingSub, SaturatingAdd, SaturatingMul, SaturatingSub,
    WrappingAdd, WrappingMul, WrappingNeg, WrappingSub,
};
pub use convert::{FromPrimitive, ToPrimitive};
pub use numeric::{
    Bounded, Num, NumAssign, NumAssignOps, NumAssignRef, NumOps, NumRef, One, RefNum, Signed,
    Unsigned, Zero,
};
pub use ops::{
    AndNot, BitOps, DivRem, Gcd, ModAdd, ModInverse, ModMul, ModPow, ModSub, Pow, RemEuclid, Square,
};
#[cfg(feature = "rand_core")]
pub use random::{
    IsProbablePrime, NextProbablePrime, ProbablePrime, Random, RandomBits, RandomMod,
};
