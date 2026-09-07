//! Core numeric vocabulary adapted from `num-traits`.

use core::ops::{
    Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Sub, SubAssign,
};

/// A value with an additive identity.
pub trait Zero: Sized + Add<Self, Output = Self> {
    /// Returns zero.
    fn zero() -> Self;

    /// Replaces this value with zero.
    fn set_zero(&mut self) {
        *self = Self::zero();
    }

    /// Returns whether this value is zero.
    fn is_zero(&self) -> bool;
}

/// A value with a multiplicative identity.
pub trait One: Sized + Mul<Self, Output = Self> {
    /// Returns one.
    fn one() -> Self;

    /// Replaces this value with one.
    fn set_one(&mut self) {
        *self = Self::one();
    }

    /// Returns whether this value is one.
    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        self == &Self::one()
    }
}

/// The five basic numeric operators.
pub trait NumOps<Rhs = Self, Output = Self>:
    Add<Rhs, Output = Output>
    + Sub<Rhs, Output = Output>
    + Mul<Rhs, Output = Output>
    + Div<Rhs, Output = Output>
    + Rem<Rhs, Output = Output>
{
}

impl<T, Rhs, Output> NumOps<Rhs, Output> for T where
    T: Add<Rhs, Output = Output>
        + Sub<Rhs, Output = Output>
        + Mul<Rhs, Output = Output>
        + Div<Rhs, Output = Output>
        + Rem<Rhs, Output = Output>
{
}

/// A [`Num`] whose basic operators accept a borrowed right-hand side.
pub trait NumRef: Num + for<'a> NumOps<&'a Self> {}

impl<T> NumRef for T where T: Num + for<'a> NumOps<&'a T> {}

/// A reference-like value whose operators accept owned and borrowed values.
pub trait RefNum<Base>: NumOps<Base, Base> + for<'a> NumOps<&'a Base, Base> {}

impl<T, Base> RefNum<Base> for T where T: NumOps<Base, Base> + for<'a> NumOps<&'a Base, Base> {}

/// The five basic assignment operators.
pub trait NumAssignOps<Rhs = Self>:
    AddAssign<Rhs> + SubAssign<Rhs> + MulAssign<Rhs> + DivAssign<Rhs> + RemAssign<Rhs>
{
}

impl<T, Rhs> NumAssignOps<Rhs> for T where
    T: AddAssign<Rhs> + SubAssign<Rhs> + MulAssign<Rhs> + DivAssign<Rhs> + RemAssign<Rhs>
{
}

/// A [`Num`] supporting all owned assignment operators.
pub trait NumAssign: Num + NumAssignOps {}

impl<T> NumAssign for T where T: Num + NumAssignOps {}

/// A [`NumAssign`] whose assignment operators accept borrowed values.
pub trait NumAssignRef: NumAssign + for<'a> NumAssignOps<&'a Self> {}

impl<T> NumAssignRef for T where T: NumAssign + for<'a> NumAssignOps<&'a T> {}

/// Base contract for numeric values.
pub trait Num: PartialEq + Zero + One + NumOps {
    /// Parsing error.
    type FromStrRadixErr;

    /// Parses a value in `radix`.
    fn from_str_radix(value: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr>;
}

/// Operations specific to signed values.
pub trait Signed: Sized + Num + Neg<Output = Self> {
    /// Returns the absolute value.
    fn abs(&self) -> Self;

    /// Returns `self - other` when positive, or zero otherwise.
    fn abs_sub(&self, other: &Self) -> Self;

    /// Returns negative one, zero, or positive one.
    fn signum(&self) -> Self;

    /// Returns whether the value is positive.
    fn is_positive(&self) -> bool;

    /// Returns whether the value is negative.
    fn is_negative(&self) -> bool;
}

/// Marker trait for numeric values which cannot be negative.
pub trait Unsigned: Num {}

#[cfg(test)]
mod tests {
    use super::{Num, NumAssignRef, NumRef, One, RefNum, Signed, Zero};
    use crate::{FixedBigInt, FixedBigUint, Word};

    type I = FixedBigInt<{ 128 / Word::BITS as usize }>;
    type U = FixedBigUint<{ 128 / Word::BITS as usize }>;

    fn assert_num_ref<T: NumRef>() {}
    fn assert_num_assign_ref<T: NumAssignRef>() {}
    fn assert_ref_num<T>()
    where
        for<'a> &'a T: RefNum<T>,
    {
    }
    fn assert_hash<T: core::hash::Hash>() {}
    fn assert_default<T: Default>() {}

    #[test]
    fn identity_default_methods_and_numeric_marker_traits_work() {
        let mut value = U::from(9_u8);
        Zero::set_zero(&mut value);
        assert!(Zero::is_zero(&value));

        One::set_one(&mut value);
        assert!(One::is_one(&value));

        assert_num_ref::<U>();
        assert_num_assign_ref::<U>();
        assert_ref_num::<U>();
        assert_hash::<I>();
        assert_hash::<U>();
        assert_default::<I>();
        assert_default::<U>();
    }

    #[test]
    fn signed_trait_methods_cover_negative_zero_and_positive_values() {
        let negative = I::from(-7_i8);
        let zero = I::zero();
        let positive = I::from(3_i8);

        assert_eq!(Signed::abs(&negative), I::from(7_i8));
        assert_eq!(Signed::abs_sub(&positive, &negative), I::from(10_i8));
        assert_eq!(Signed::abs_sub(&negative, &positive), zero);
        assert_eq!(Signed::signum(&negative), I::from(-1_i8));
        assert_eq!(Signed::signum(&zero), zero);
        assert_eq!(Signed::signum(&positive), I::from(1_i8));
        assert!(Signed::is_negative(&negative));
        assert!(Signed::is_positive(&positive));
    }

    #[test]
    fn num_parsing_contract_calls_the_concrete_parser() {
        assert_eq!(
            <U as Num>::from_str_radix("ff", 16).expect("valid hexadecimal"),
            U::from(255_u16)
        );
    }
}
