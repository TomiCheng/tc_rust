//! Overflow policies: checked, overflowing, wrapping and saturating arithmetic.

use core::ops::{Add, Div, Mul, Neg, Rem, Sub};

/// Checked addition.
pub trait CheckedAdd: Sized + Add<Self, Output = Self> {
    /// Returns the sum, or `None` if it is outside the numeric range.
    fn checked_add(&self, rhs: &Self) -> Option<Self>;
}

/// Checked subtraction.
pub trait CheckedSub: Sized + Sub<Self, Output = Self> {
    /// Returns the difference, or `None` if it is outside the numeric range.
    fn checked_sub(&self, rhs: &Self) -> Option<Self>;
}

/// Checked multiplication.
pub trait CheckedMul: Sized + Mul<Self, Output = Self> {
    /// Returns the product, or `None` if it is outside the numeric range.
    fn checked_mul(&self, rhs: &Self) -> Option<Self>;
}

/// Checked division.
pub trait CheckedDiv: Sized + Div<Self, Output = Self> {
    /// Returns the quotient, or `None` for division by zero or overflow.
    fn checked_div(&self, rhs: &Self) -> Option<Self>;
}

/// Checked remainder.
pub trait CheckedRem: Sized + Rem<Self, Output = Self> {
    /// Returns the remainder, or `None` when `rhs` is zero.
    fn checked_rem(&self, rhs: &Self) -> Option<Self>;
}

/// Checked negation.
pub trait CheckedNeg: Sized + Neg<Output = Self> {
    /// Returns the negated value, or `None` when it is not representable.
    fn checked_neg(&self) -> Option<Self>;
}

/// Checked left shift.
pub trait CheckedShl: Sized {
    /// Returns the shifted value, or `None` when the shift or result is outside
    /// the numeric range.
    fn checked_shl(&self, rhs: u32) -> Option<Self>;
}

/// Checked right shift.
pub trait CheckedShr: Sized {
    /// Returns the shifted value, or `None` when the shift is outside the
    /// numeric range.
    fn checked_shr(&self, rhs: u32) -> Option<Self>;
}

/// Addition with an overflow flag.
pub trait OverflowingAdd: Sized + Add<Self, Output = Self> {
    /// Returns the wrapped sum and whether overflow occurred.
    fn overflowing_add(&self, rhs: &Self) -> (Self, bool);
}

/// Subtraction with an overflow flag.
pub trait OverflowingSub: Sized + Sub<Self, Output = Self> {
    /// Returns the wrapped difference and whether overflow or underflow occurred.
    fn overflowing_sub(&self, rhs: &Self) -> (Self, bool);
}

/// Multiplication with an overflow flag.
pub trait OverflowingMul: Sized + Mul<Self, Output = Self> {
    /// Returns the wrapped product and whether overflow occurred.
    fn overflowing_mul(&self, rhs: &Self) -> (Self, bool);
}

/// Wrapping addition.
pub trait WrappingAdd: Sized + Add<Self, Output = Self> {
    /// Returns the sum modulo the type width.
    fn wrapping_add(&self, rhs: &Self) -> Self;
}

/// Wrapping subtraction.
pub trait WrappingSub: Sized + Sub<Self, Output = Self> {
    /// Returns the difference modulo the type width.
    fn wrapping_sub(&self, rhs: &Self) -> Self;
}

/// Wrapping multiplication.
pub trait WrappingMul: Sized + Mul<Self, Output = Self> {
    /// Returns the product modulo the type width.
    fn wrapping_mul(&self, rhs: &Self) -> Self;
}

/// Wrapping negation.
pub trait WrappingNeg: Sized + Neg<Output = Self> {
    /// Returns the two's-complement negation modulo the type width.
    fn wrapping_neg(&self) -> Self;
}

/// Saturating addition.
pub trait SaturatingAdd: Sized + Add<Self, Output = Self> {
    /// Returns the sum clamped to the numeric range.
    fn saturating_add(&self, rhs: &Self) -> Self;
}

/// Saturating subtraction.
pub trait SaturatingSub: Sized + Sub<Self, Output = Self> {
    /// Returns the difference clamped to the numeric range.
    fn saturating_sub(&self, rhs: &Self) -> Self;
}

/// Saturating multiplication.
pub trait SaturatingMul: Sized + Mul<Self, Output = Self> {
    /// Returns the product clamped to the numeric range.
    fn saturating_mul(&self, rhs: &Self) -> Self;
}

#[cfg(test)]
mod tests {
    use super::{
        CheckedAdd, CheckedDiv, CheckedMul, CheckedNeg, CheckedRem, CheckedShl, CheckedShr,
        CheckedSub, OverflowingAdd, OverflowingMul, OverflowingSub, SaturatingAdd, SaturatingMul,
        SaturatingSub, WrappingAdd, WrappingMul, WrappingNeg, WrappingSub,
    };
    use crate::{FixedBigInt, FixedBigUint, Word};

    type I = FixedBigInt<{ 128 / Word::BITS as usize }>;
    type U = FixedBigUint<{ 128 / Word::BITS as usize }>;

    #[test]
    fn addition_contracts_cover_each_overflow_policy() {
        let max = U::max_value();
        let one = U::from(1_u8);

        assert_eq!(CheckedAdd::checked_add(&max, &one), None);
        assert_eq!(CheckedSub::checked_sub(&U::zero(), &one), None);
        assert_eq!(
            OverflowingAdd::overflowing_add(&max, &one),
            (U::zero(), true)
        );
        assert_eq!(WrappingAdd::wrapping_add(&max, &one), U::zero());
        assert_eq!(SaturatingAdd::saturating_add(&max, &one), max);
    }

    #[test]
    fn checked_wrapping_overflowing_and_saturating_contracts_cover_boundaries() {
        let max = U::max_value();
        let zero = U::zero();
        let one = U::from(1_u8);
        let two = U::from(2_u8);

        assert_eq!(CheckedMul::checked_mul(&max, &two), None);
        assert_eq!(
            OverflowingMul::overflowing_mul(&max, &two),
            (max - one, true)
        );
        assert_eq!(WrappingMul::wrapping_mul(&max, &two), max - one);
        assert_eq!(SaturatingMul::saturating_mul(&max, &two), max);
        assert_eq!(OverflowingSub::overflowing_sub(&zero, &one), (max, true));
        assert_eq!(WrappingSub::wrapping_sub(&zero, &one), max);
        assert_eq!(SaturatingSub::saturating_sub(&zero, &one), zero);
        assert_eq!(CheckedDiv::checked_div(&one, &zero), None);
        assert_eq!(CheckedRem::checked_rem(&one, &zero), None);
        assert_eq!(CheckedShl::checked_shl(&one, 127), Some(one << 127));
        assert_eq!(CheckedShl::checked_shl(&max, 1), None);
        assert_eq!(CheckedShr::checked_shr(&one, 128), None);

        let signed_min = I::min_value();
        assert_eq!(CheckedNeg::checked_neg(&signed_min), None);
        assert_eq!(WrappingNeg::wrapping_neg(&signed_min), signed_min);
        assert_eq!(
            CheckedShl::checked_shl(&I::from(1_i8), 126),
            Some(I::from(1_i8) << 126)
        );
        assert_eq!(CheckedShl::checked_shl(&I::from(1_i8), 127), None);
        assert_eq!(CheckedShr::checked_shr(&I::from(-1_i8), 128), None);
    }
}
