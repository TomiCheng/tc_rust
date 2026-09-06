//! Multiplication for [`FixedBigInt`].

use core::ops::{Mul, MulAssign};

use crate::traits::{CheckedMul, OverflowingMul, SaturatingMul, Square, WrappingMul};
use crate::{FixedBigInt, Limb, Word, arithmetic};

impl<const N: usize> FixedBigInt<N> {
    /// Returns `self * self`.
    pub fn square(&self) -> Self {
        *self * *self
    }

    /// Returns `self * rhs`, or `None` when the product does not fit.
    pub fn checked_mul(&self, rhs: &Self) -> Option<Self> {
        let negative = self.is_negative() != rhs.is_negative();
        let (magnitude, overflow) = arithmetic::fixed_mul(&self.magnitude(), &rhs.magnitude());
        if overflow {
            return None;
        }
        Self::from_sign_magnitude(negative, magnitude)
    }
}

impl<const N: usize> Mul for FixedBigInt<N> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.checked_mul(&rhs)
            .expect("attempted to multiply with overflow")
    }
}

impl<const N: usize> Mul<&FixedBigInt<N>> for FixedBigInt<N> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self * *rhs
    }
}

impl<const N: usize> Mul<FixedBigInt<N>> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    fn mul(self, rhs: FixedBigInt<N>) -> Self::Output {
        *self * rhs
    }
}

impl<const N: usize> Mul<&FixedBigInt<N>> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    fn mul(self, rhs: &FixedBigInt<N>) -> Self::Output {
        *self * *rhs
    }
}

impl<const N: usize> MulAssign for FixedBigInt<N> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<const N: usize> MulAssign<&FixedBigInt<N>> for FixedBigInt<N> {
    fn mul_assign(&mut self, rhs: &FixedBigInt<N>) {
        *self = *self * *rhs;
    }
}

macro_rules! impl_mul_unsigned_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl<const N: usize> Mul<$primitive> for FixedBigInt<N> {
                type Output = Self;

                fn mul(self, rhs: $primitive) -> Self::Output {
                    checked_mul_u128(&self, rhs as u128)
                        .expect("attempted to multiply with overflow")
                }
            }

            impl<const N: usize> Mul<$primitive> for &FixedBigInt<N> {
                type Output = FixedBigInt<N>;

                fn mul(self, rhs: $primitive) -> Self::Output {
                    *self * rhs
                }
            }

            impl<const N: usize> MulAssign<$primitive> for FixedBigInt<N> {
                fn mul_assign(&mut self, rhs: $primitive) {
                    *self = *self * rhs;
                }
            }
        )*
    };
}

impl_mul_unsigned_primitive!(u8, u16, u32, u64, u128);

impl<const N: usize> Square for FixedBigInt<N> {
    type Output = Self;

    fn square(&self) -> Self::Output {
        FixedBigInt::square(self)
    }
}

impl<const N: usize> CheckedMul for FixedBigInt<N> {
    fn checked_mul(&self, rhs: &Self) -> Option<Self> {
        FixedBigInt::checked_mul(self, rhs)
    }
}

impl<const N: usize> OverflowingMul for FixedBigInt<N> {
    fn overflowing_mul(&self, rhs: &Self) -> (Self, bool) {
        let limbs = arithmetic::fixed_mul(self.limbs.as_limbs(), rhs.limbs.as_limbs()).0;
        (
            Self {
                limbs: crate::LimbArray::new(limbs),
            },
            self.checked_mul(rhs).is_none(),
        )
    }
}

impl<const N: usize> WrappingMul for FixedBigInt<N> {
    fn wrapping_mul(&self, rhs: &Self) -> Self {
        self.overflowing_mul(rhs).0
    }
}

impl<const N: usize> SaturatingMul for FixedBigInt<N> {
    fn saturating_mul(&self, rhs: &Self) -> Self {
        self.checked_mul(rhs).unwrap_or_else(|| {
            if self.is_negative() != rhs.is_negative() {
                Self::min_value()
            } else {
                Self::max_value()
            }
        })
    }
}

fn checked_mul_u128<const N: usize>(lhs: &FixedBigInt<N>, mut rhs: u128) -> Option<FixedBigInt<N>> {
    let mut rhs_limbs = [Limb::new(0); N];
    for limb in &mut rhs_limbs {
        *limb = Limb::new(rhs as Word);
        rhs >>= Word::BITS;
    }
    if rhs != 0 && !lhs.is_zero() {
        return None;
    }
    let (magnitude, overflow) = arithmetic::fixed_mul(&lhs.magnitude(), &rhs_limbs);
    if overflow {
        return None;
    }
    FixedBigInt::from_sign_magnitude(lhs.is_negative(), magnitude)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ToPrimitive;

    #[test]
    fn primitive_multiplication_and_assignment_support_every_width() {
        assert_eq!(
            FixedBigInt::<4>::from(-3_i8) * 2_u8,
            FixedBigInt::from(-6_i8)
        );
        assert_eq!(
            &FixedBigInt::<4>::from(-3_i8) * 3_u16,
            FixedBigInt::from(-9_i8)
        );
        assert_eq!(
            FixedBigInt::<4>::from(-3_i8) * 4_u32,
            FixedBigInt::from(-12_i8)
        );
        assert_eq!(
            &FixedBigInt::<4>::from(-3_i8) * 5_u64,
            FixedBigInt::from(-15_i8)
        );
        assert_eq!(
            FixedBigInt::<8>::from(-1_i8) * u128::MAX,
            -FixedBigInt::<8>::from(u128::MAX)
        );

        let mut value = FixedBigInt::<4>::from(-2_i8);
        value *= 2_u8;
        value *= 3_u16;
        value *= 4_u32;
        value *= 5_u64;
        value *= 6_u128;
        assert_eq!(value, FixedBigInt::from(-1_440_i16));
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn fixed_multiplication_supports_all_ownership_and_assignment_forms() {
        type I = FixedBigInt<4>;
        let left = I::from(-20_i8);
        let right = I::from(6_i8);
        let expected = I::from(-120_i8);
        assert_eq!(left * right, expected);
        assert_eq!(left * &right, expected);
        assert_eq!(&left * right, expected);
        assert_eq!(&left * &right, expected);

        let mut value = left;
        value *= right;
        assert_eq!(value, expected);
        value = left;
        value *= &right;
        assert_eq!(value, expected);
    }

    #[test]
    fn fixed_multiplication_matches_i128() {
        type I = FixedBigInt<{ 128 / Word::BITS as usize }>;
        assert_eq!(
            (I::from(-1_000_000_i64) * I::from(37_u8)).to_i128(),
            Some(-37_000_000)
        );
    }

    #[test]
    fn checked_wrapping_overflowing_and_saturating_products_are_distinct() {
        type I = FixedBigInt<1>;
        let max = I::max_value();
        let two = I::from(2_i8);
        let (wrapped, overflow) = max.overflowing_mul(&two);
        assert!(overflow);
        assert_eq!(wrapped, max.wrapping_mul(&two));
        assert_eq!(max.checked_mul(&two), None);
        assert_eq!(max.saturating_mul(&two), max);
        assert_eq!(I::min_value().saturating_mul(&two), I::min_value());
    }

    #[test]
    #[should_panic(expected = "attempted to multiply with overflow")]
    fn primitive_multiplication_rejects_overflow() {
        let _ = FixedBigInt::<1>::max_value() * 2_u8;
    }
}
