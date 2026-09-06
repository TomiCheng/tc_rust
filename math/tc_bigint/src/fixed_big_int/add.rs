//! Addition for [`FixedBigInt`].

use core::ops::{Add, AddAssign};

use crate::traits::{CheckedAdd, OverflowingAdd, SaturatingAdd, WrappingAdd};
use crate::{FixedBigInt, Limb, Word};

impl<const N: usize> Add for FixedBigInt<N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(&rhs)
            .expect("attempted to add with overflow")
    }
}

impl<const N: usize> Add<&FixedBigInt<N>> for FixedBigInt<N> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self + *rhs
    }
}

impl<const N: usize> Add<FixedBigInt<N>> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    fn add(self, rhs: FixedBigInt<N>) -> Self::Output {
        *self + rhs
    }
}

impl<const N: usize> Add<&FixedBigInt<N>> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    fn add(self, rhs: &FixedBigInt<N>) -> Self::Output {
        *self + *rhs
    }
}

impl<const N: usize> AddAssign for FixedBigInt<N> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<const N: usize> AddAssign<&FixedBigInt<N>> for FixedBigInt<N> {
    fn add_assign(&mut self, rhs: &FixedBigInt<N>) {
        *self = *self + *rhs;
    }
}

macro_rules! impl_add_unsigned_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl<const N: usize> Add<$primitive> for FixedBigInt<N> {
                type Output = Self;

                #[inline]
                fn add(self, rhs: $primitive) -> Self::Output {
                    checked_add_u128(&self, rhs as u128)
                        .expect("attempted to add with overflow")
                }
            }

            impl<const N: usize> Add<$primitive> for &FixedBigInt<N> {
                type Output = FixedBigInt<N>;

                #[inline]
                fn add(self, rhs: $primitive) -> Self::Output {
                    *self + rhs
                }
            }

            impl<const N: usize> AddAssign<$primitive> for FixedBigInt<N> {
                #[inline]
                fn add_assign(&mut self, rhs: $primitive) {
                    *self = *self + rhs;
                }
            }
        )*
    };
}

impl_add_unsigned_primitive!(u8, u16, u32, u64, u128);

impl<const N: usize> CheckedAdd for FixedBigInt<N> {
    fn checked_add(&self, rhs: &Self) -> Option<Self> {
        let (limbs, _) = self.limbs.add(&rhs.limbs);
        let overflow = self.is_negative() == rhs.is_negative()
            && crate::FixedBigInt::is_negative_limbs(limbs.as_limbs()) != self.is_negative();
        (!overflow).then_some(Self { limbs })
    }
}

impl<const N: usize> OverflowingAdd for FixedBigInt<N> {
    fn overflowing_add(&self, rhs: &Self) -> (Self, bool) {
        let (limbs, _) = self.limbs.add(&rhs.limbs);
        let overflow = self.is_negative() == rhs.is_negative()
            && crate::FixedBigInt::is_negative_limbs(limbs.as_limbs()) != self.is_negative();
        (Self { limbs }, overflow)
    }
}

impl<const N: usize> WrappingAdd for FixedBigInt<N> {
    fn wrapping_add(&self, rhs: &Self) -> Self {
        self.overflowing_add(rhs).0
    }
}

impl<const N: usize> SaturatingAdd for FixedBigInt<N> {
    fn saturating_add(&self, rhs: &Self) -> Self {
        match self.checked_add(rhs) {
            Some(value) => value,
            None if self.is_negative() => Self::min_value(),
            None => Self::max_value(),
        }
    }
}

#[inline]
fn checked_add_u128<const N: usize>(lhs: &FixedBigInt<N>, mut rhs: u128) -> Option<FixedBigInt<N>> {
    let width = N * Word::BITS as usize;
    if width == 0 {
        return (rhs == 0).then_some(*lhs);
    }

    if width <= 128 {
        let lhs_value = lhs
            .checked_i128()
            .expect("a fixed integer of at most 128 bits always fits i128");
        let max = if width == 128 {
            i128::MAX as u128
        } else {
            (1_u128 << (width - 1)) - 1
        };
        let headroom = if lhs_value < 0 {
            max + lhs_value.unsigned_abs()
        } else {
            max - lhs_value as u128
        };
        if rhs > headroom {
            return None;
        }
    }

    let mut limbs = lhs.limbs.into_limbs();
    let mut carry = Limb::new(0);
    for limb in &mut limbs {
        let rhs_limb = Limb::new(rhs as Word);
        rhs >>= Word::BITS;
        (*limb, carry) = limb.carrying_add(rhs_limb, carry);
    }

    if width > 128 && !lhs.is_negative() && crate::FixedBigInt::is_negative_limbs(&limbs) {
        return None;
    }
    Some(FixedBigInt {
        limbs: crate::LimbArray::new(limbs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_addition_supports_every_unsigned_width_directly() {
        assert_eq!(
            FixedBigInt::<4>::from(-1_i8) + 2_u8,
            FixedBigInt::from(1_i8)
        );
        assert_eq!(
            &FixedBigInt::<4>::from(-1_i8) + 2_u16,
            FixedBigInt::from(1_i8)
        );
        assert_eq!(
            FixedBigInt::<4>::from(-1_i8) + 2_u32,
            FixedBigInt::from(1_i8)
        );
        assert_eq!(
            &FixedBigInt::<4>::from(-1_i8) + 2_u64,
            FixedBigInt::from(1_i8)
        );
        assert_eq!(
            FixedBigInt::<4>::from(-1_i8) + 2_u128,
            FixedBigInt::from(1_i8)
        );

        let mut value = FixedBigInt::<8>::from(-1_i8);
        value += u8::MAX;
        value += u16::MAX;
        value += u32::MAX;
        value += u64::MAX;
        value += u128::MAX;
        assert_eq!(
            value,
            FixedBigInt::<8>::from(-1_i8)
                + FixedBigInt::from(u8::MAX)
                + FixedBigInt::from(u16::MAX)
                + FixedBigInt::from(u32::MAX)
                + FixedBigInt::from(u64::MAX)
                + FixedBigInt::from(u128::MAX)
        );
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn fixed_addition_supports_all_ownership_and_assignment_forms() {
        type I = FixedBigInt<4>;
        let left = I::from(-20_i8);
        let right = I::from(6_i8);
        let expected = I::from(-14_i8);
        assert_eq!(left + right, expected);
        assert_eq!(left + &right, expected);
        assert_eq!(&left + right, expected);
        assert_eq!(&left + &right, expected);

        let mut value = left;
        value += right;
        assert_eq!(value, expected);
        value = left;
        value += &right;
        assert_eq!(value, expected);
    }

    #[test]
    fn signed_checked_wrapping_overflowing_and_saturating_add_are_distinct() {
        type I = FixedBigInt<2>;
        let max = I::max_value();
        let one = I::from(1_u8);
        assert_eq!(max.checked_add(&one), None);
        assert_eq!(max.overflowing_add(&one), (I::min_value(), true));
        assert_eq!(max.wrapping_add(&one), I::min_value());
        assert_eq!(max.saturating_add(&one), max);
    }

    #[test]
    #[should_panic(expected = "attempted to add with overflow")]
    fn fixed_addition_rejects_overflow() {
        type I = FixedBigInt<2>;
        let _ = I::max_value() + I::from(1_u8);
    }

    #[test]
    fn minimum_i128_plus_maximum_u128_is_maximum_i128() {
        let result = FixedBigInt::<{ 128 / Word::BITS as usize }>::from(i128::MIN) + u128::MAX;
        assert_eq!(result, FixedBigInt::from(i128::MAX));
    }

    #[test]
    #[should_panic(expected = "attempted to add with overflow")]
    fn primitive_addition_rejects_signed_overflow() {
        let _ = FixedBigInt::<{ 128 / Word::BITS as usize }>::zero() + u128::MAX;
    }
}
