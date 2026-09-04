//! Multiplication for [`BigInt`].

use core::ops::{Mul, MulAssign};

use crate::traits::{CheckedMul, OverflowingMul, SaturatingMul, Square, WrappingMul};
use crate::{BigInt, Limb, Word, arithmetic};

impl BigInt {
    /// Returns `self * self`.
    pub fn square(&self) -> Self {
        let (_, magnitude) = self.sign_magnitude();
        Self::from_sign_magnitude(false, arithmetic::square(&magnitude))
    }

    fn mul_ref(lhs: &Self, rhs: &Self) -> Self {
        let (lhs_negative, lhs_magnitude) = lhs.sign_magnitude();
        let (rhs_negative, rhs_magnitude) = rhs.sign_magnitude();
        Self::from_sign_magnitude(
            lhs_negative != rhs_negative,
            arithmetic::mul(&lhs_magnitude, &rhs_magnitude),
        )
    }
}

macro_rules! impl_mul {
    ($lhs:ty, $rhs:ty) => {
        impl Mul<$rhs> for $lhs {
            type Output = BigInt;

            fn mul(self, rhs: $rhs) -> Self::Output {
                BigInt::mul_ref(&self, &rhs)
            }
        }
    };
}

impl_mul!(&BigInt, &BigInt);
impl_mul!(&BigInt, BigInt);
impl_mul!(BigInt, &BigInt);
impl_mul!(BigInt, BigInt);

impl MulAssign<&BigInt> for BigInt {
    fn mul_assign(&mut self, rhs: &BigInt) {
        *self = &*self * rhs;
    }
}

impl MulAssign for BigInt {
    fn mul_assign(&mut self, rhs: Self) {
        *self *= &rhs;
    }
}

macro_rules! impl_mul_unsigned_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl Mul<$primitive> for BigInt {
                type Output = Self;

                fn mul(self, rhs: $primitive) -> Self::Output {
                    mul_u128(&self, rhs as u128)
                }
            }

            impl Mul<$primitive> for &BigInt {
                type Output = BigInt;

                fn mul(self, rhs: $primitive) -> Self::Output {
                    mul_u128(self, rhs as u128)
                }
            }

            impl MulAssign<$primitive> for BigInt {
                fn mul_assign(&mut self, rhs: $primitive) {
                    *self = mul_u128(self, rhs as u128);
                }
            }
        )*
    };
}

impl_mul_unsigned_primitive!(u8, u16, u32, u64, u128);

impl Square for BigInt {
    type Output = Self;

    fn square(&self) -> Self::Output {
        BigInt::square(self)
    }
}

impl CheckedMul for BigInt {
    fn checked_mul(&self, rhs: &Self) -> Option<Self> {
        Some(self * rhs)
    }
}

impl OverflowingMul for BigInt {
    fn overflowing_mul(&self, rhs: &Self) -> (Self, bool) {
        (self * rhs, false)
    }
}

impl WrappingMul for BigInt {
    fn wrapping_mul(&self, rhs: &Self) -> Self {
        self * rhs
    }
}

impl SaturatingMul for BigInt {
    fn saturating_mul(&self, rhs: &Self) -> Self {
        self * rhs
    }
}

fn mul_u128(lhs: &BigInt, rhs: u128) -> BigInt {
    let (negative, magnitude) = lhs.sign_magnitude();

    #[cfg(target_pointer_width = "64")]
    let words = [Limb(rhs as Word), Limb((rhs >> 64) as Word)];

    #[cfg(not(target_pointer_width = "64"))]
    let words = [
        Limb(rhs as Word),
        Limb((rhs >> 32) as Word),
        Limb((rhs >> 64) as Word),
        Limb((rhs >> 96) as Word),
    ];

    let used = words
        .iter()
        .rposition(|word| word.0 != 0)
        .map_or(0, |index| index + 1);
    BigInt::from_sign_magnitude(negative, arithmetic::mul(&magnitude, &words[..used]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_multiplication_and_assignment_support_every_width() {
        assert_eq!(BigInt::from(-3_i8) * 2_u8, BigInt::from(-6_i8));
        assert_eq!(&BigInt::from(-3_i8) * 3_u16, BigInt::from(-9_i8));
        assert_eq!(BigInt::from(-3_i8) * 4_u32, BigInt::from(-12_i8));
        assert_eq!(&BigInt::from(-3_i8) * 5_u64, BigInt::from(-15_i8));
        assert_eq!(
            BigInt::from(-3_i8) * u128::MAX,
            -(BigInt::from(u128::MAX) * BigInt::from(3_u8))
        );

        let mut value = BigInt::from(-2_i8);
        value *= 2_u8;
        value *= 3_u16;
        value *= 4_u32;
        value *= 5_u64;
        value *= 6_u128;
        assert_eq!(value, BigInt::from(-1_440_i16));
    }

    #[test]
    fn bigint_multiplication_supports_all_ownership_and_assignment_forms() {
        let left = BigInt::from(-20_i8);
        let right = BigInt::from(6_i8);
        let expected = BigInt::from(-120_i8);
        assert_eq!(&left * &right, expected);
        assert_eq!(&left * right.clone(), expected);
        assert_eq!(left.clone() * &right, expected);
        assert_eq!(left.clone() * right.clone(), expected);

        let mut value = left;
        value *= &right;
        assert_eq!(value, expected);
        value = BigInt::from(-20_i8);
        value *= right;
        assert_eq!(value, expected);
    }

    #[test]
    fn explicit_square_matches_general_multiplication() {
        let value = (BigInt::from(1_u8) << 130) + BigInt::from(17_u8);
        let distinct_copy = value.clone();

        assert_eq!(&value * &distinct_copy, value.square());
    }
}
