//! Integer capabilities shared by the prime algorithms.

use core::ops::{Rem, Shl, Shr};

use tc_bigint::{
    BitOps, CheckedAdd, CheckedMul, CheckedShl, CheckedSub, FromPrimitive, Gcd, ModMul, ModPow,
    NumRef, RandomMod, ToPrimitive,
};

use crate::PrimeError;

/// Trait bundle required by the generic FIPS prime algorithms.
///
/// `tc_bigint::BigUint` and [`tc_bigint::FixedBigUint`] satisfy this trait
/// through its blanket implementation. Callers normally use this trait only as
/// a bound when wrapping the functions exported by this crate.
pub trait PrimeInteger:
    NumRef
    + Clone
    + Ord
    + BitOps<Output = Self>
    + Gcd<Output = Self>
    + ModPow<Output = Self>
    + ModMul<Output = Self>
    + RandomMod
    + ToPrimitive
    + FromPrimitive
    + CheckedAdd
    + CheckedSub
    + CheckedMul
    + CheckedShl
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + Rem<u32, Output = Self>
{
}

impl<T> PrimeInteger for T where
    T: NumRef
        + Clone
        + Ord
        + BitOps<Output = T>
        + Gcd<Output = T>
        + ModPow<Output = T>
        + ModMul<Output = T>
        + RandomMod
        + ToPrimitive
        + FromPrimitive
        + CheckedAdd
        + CheckedSub
        + CheckedMul
        + CheckedShl
        + Shl<usize, Output = T>
        + Shr<usize, Output = T>
        + Rem<u32, Output = T>
{
}

pub(crate) fn integer<T: PrimeInteger>(value: u32) -> Result<T, PrimeError> {
    T::from_u32(value).ok_or(PrimeError::Overflow)
}

pub(crate) fn check_candidate<T: PrimeInteger>(candidate: &T) -> Result<(), PrimeError> {
    (candidate.bit_length() >= 2)
        .then_some(())
        .ok_or(PrimeError::InvalidCandidate)
}
