//! Division and remainder for [`FixedBigInt`].

use core::ops::{Div, DivAssign, Rem, RemAssign};

use crate::traits::{CheckedDiv, CheckedRem, DivRem, RemEuclid};
use crate::{FixedBigInt, Limb, Word};

impl<const N: usize> FixedBigInt<N> {
    /// Returns the truncated quotient and remainder together.
    pub fn div_rem(&self, rhs: &Self) -> (Self, Self) {
        let (quotient, remainder) = crate::LimbArray::new(self.magnitude())
            .div_rem(&crate::LimbArray::new(rhs.magnitude()));
        let quotient = Self::from_sign_magnitude(
            self.is_negative() != rhs.is_negative(),
            quotient.into_limbs(),
        )
        .expect("attempted to divide with overflow");
        let remainder = Self::from_sign_magnitude(self.is_negative(), remainder.into_limbs())
            .expect("remainder always fits the dividend type");
        (quotient, remainder)
    }

    /// Returns the least non-negative remainder.
    pub fn rem_euclid(&self, divisor: &Self) -> Self {
        assert!(
            !divisor.is_zero(),
            "attempted to calculate remainder with zero"
        );
        let remainder = *self % *divisor;
        if remainder.is_negative() {
            if divisor.is_negative() {
                remainder - *divisor
            } else {
                remainder + *divisor
            }
        } else {
            remainder
        }
    }
}

impl<const N: usize> Div for FixedBigInt<N> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.div_rem(&rhs).0
    }
}

impl<const N: usize> Rem for FixedBigInt<N> {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        self.div_rem(&rhs).1
    }
}

macro_rules! impl_borrowed_division {
    ($trait:ident, $method:ident, $operator:tt) => {
        impl<const N: usize> $trait<&FixedBigInt<N>> for FixedBigInt<N> {
            type Output = FixedBigInt<N>;

            fn $method(self, rhs: &FixedBigInt<N>) -> Self::Output {
                self $operator *rhs
            }
        }

        impl<const N: usize> $trait<FixedBigInt<N>> for &FixedBigInt<N> {
            type Output = FixedBigInt<N>;

            fn $method(self, rhs: FixedBigInt<N>) -> Self::Output {
                *self $operator rhs
            }
        }

        impl<const N: usize> $trait<&FixedBigInt<N>> for &FixedBigInt<N> {
            type Output = FixedBigInt<N>;

            fn $method(self, rhs: &FixedBigInt<N>) -> Self::Output {
                *self $operator *rhs
            }
        }
    };
}

impl_borrowed_division!(Div, div, /);
impl_borrowed_division!(Rem, rem, %);

impl<const N: usize> DivAssign for FixedBigInt<N> {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<const N: usize> DivAssign<&FixedBigInt<N>> for FixedBigInt<N> {
    fn div_assign(&mut self, rhs: &FixedBigInt<N>) {
        *self = *self / *rhs;
    }
}

impl<const N: usize> RemAssign for FixedBigInt<N> {
    fn rem_assign(&mut self, rhs: Self) {
        *self = *self % rhs;
    }
}

impl<const N: usize> RemAssign<&FixedBigInt<N>> for FixedBigInt<N> {
    fn rem_assign(&mut self, rhs: &FixedBigInt<N>) {
        *self = *self % *rhs;
    }
}

macro_rules! impl_division_unsigned_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl<const N: usize> Div<$primitive> for FixedBigInt<N> {
                type Output = Self;

                fn div(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(&self, rhs as u128).0
                }
            }

            impl<const N: usize> Div<$primitive> for &FixedBigInt<N> {
                type Output = FixedBigInt<N>;

                fn div(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(self, rhs as u128).0
                }
            }

            impl<const N: usize> Rem<$primitive> for FixedBigInt<N> {
                type Output = Self;

                fn rem(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(&self, rhs as u128).1
                }
            }

            impl<const N: usize> Rem<$primitive> for &FixedBigInt<N> {
                type Output = FixedBigInt<N>;

                fn rem(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(self, rhs as u128).1
                }
            }

            impl<const N: usize> DivAssign<$primitive> for FixedBigInt<N> {
                fn div_assign(&mut self, rhs: $primitive) {
                    *self = div_rem_u128(self, rhs as u128).0;
                }
            }

            impl<const N: usize> RemAssign<$primitive> for FixedBigInt<N> {
                fn rem_assign(&mut self, rhs: $primitive) {
                    *self = div_rem_u128(self, rhs as u128).1;
                }
            }
        )*
    };
}

impl_division_unsigned_primitive!(u8, u16, u32, u64, u128);

impl<const N: usize> DivRem for FixedBigInt<N> {
    type Quotient = Self;
    type Remainder = Self;

    fn div_rem(&self, rhs: &Self) -> (Self::Quotient, Self::Remainder) {
        FixedBigInt::div_rem(self, rhs)
    }
}

impl<const N: usize> RemEuclid for FixedBigInt<N> {
    type Output = Self;

    fn rem_euclid(&self, rhs: &Self) -> Self::Output {
        FixedBigInt::rem_euclid(self, rhs)
    }
}

impl<const N: usize> CheckedDiv for FixedBigInt<N> {
    fn checked_div(&self, rhs: &Self) -> Option<Self> {
        if rhs.is_zero() || (*self == Self::min_value() && *rhs == Self::from(-1_i8)) {
            return None;
        }
        Some(self.div_rem(rhs).0)
    }
}

impl<const N: usize> CheckedRem for FixedBigInt<N> {
    fn checked_rem(&self, rhs: &Self) -> Option<Self> {
        if rhs.is_zero() || (*self == Self::min_value() && *rhs == Self::from(-1_i8)) {
            return None;
        }
        Some(self.div_rem(rhs).1)
    }
}

fn div_rem_u128<const N: usize>(
    value: &FixedBigInt<N>,
    mut divisor: u128,
) -> (FixedBigInt<N>, FixedBigInt<N>) {
    assert_ne!(divisor, 0, "attempted to divide by zero");
    let mut divisor_limbs = [Limb::new(0); N];
    for limb in &mut divisor_limbs {
        *limb = Limb::new(divisor as Word);
        divisor >>= Word::BITS;
    }
    if divisor != 0 {
        return (FixedBigInt::zero(), *value);
    }

    let (quotient, remainder) =
        crate::LimbArray::new(value.magnitude()).div_rem(&crate::LimbArray::new(divisor_limbs));
    let quotient = FixedBigInt::from_sign_magnitude(value.is_negative(), quotient.into_limbs())
        .expect("division by a positive primitive cannot overflow");
    let remainder = FixedBigInt::from_sign_magnitude(value.is_negative(), remainder.into_limbs())
        .expect("remainder always fits the dividend type");
    (quotient, remainder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ToPrimitive;

    #[test]
    fn primitive_division_remainder_and_assignment_support_every_width() {
        let value = FixedBigInt::<4>::from(-120_i8);
        assert_eq!(value / 2_u8, FixedBigInt::from(-60_i8));
        assert_eq!(&value / 3_u16, FixedBigInt::from(-40_i8));
        assert_eq!(value / 4_u32, FixedBigInt::from(-30_i8));
        assert_eq!(&value / 5_u64, FixedBigInt::from(-24_i8));
        assert_eq!(
            FixedBigInt::<4>::from(-120_i8) / u128::MAX,
            FixedBigInt::zero()
        );

        assert_eq!(value % 7_u8, FixedBigInt::from(-1_i8));
        assert_eq!(&value % 11_u16, FixedBigInt::from(-10_i8));
        assert_eq!(value % 13_u32, FixedBigInt::from(-3_i8));
        assert_eq!(&value % 17_u64, FixedBigInt::from(-1_i8));
        assert_eq!(
            FixedBigInt::<4>::from(-120_i8) % u128::MAX,
            FixedBigInt::from(-120_i8)
        );

        let mut quotient = FixedBigInt::<4>::from(-120_i8);
        quotient /= 3_u8;
        quotient /= 2_u16;
        quotient /= 2_u32;
        quotient /= 2_u64;
        quotient /= 5_u128;
        assert_eq!(quotient, FixedBigInt::from(-1_i8));

        let mut remainder = FixedBigInt::<4>::from(-120_i8);
        remainder %= 17_u8;
        remainder %= 7_u16;
        remainder %= 5_u32;
        remainder %= 3_u64;
        remainder %= 2_u128;
        assert_eq!(remainder, FixedBigInt::from(-1_i8));
    }

    #[test]
    fn checked_division_rejects_zero_and_signed_overflow() {
        type I = FixedBigInt<2>;
        let value = I::from(-17_i8);
        assert_eq!(value.checked_div(&I::from(5_i8)), Some(I::from(-3_i8)));
        assert_eq!(value.checked_rem(&I::from(5_i8)), Some(I::from(-2_i8)));
        assert_eq!(value.checked_div(&I::zero()), None);
        assert_eq!(value.checked_rem(&I::zero()), None);
        assert_eq!(I::min_value().checked_div(&I::from(-1_i8)), None);
        assert_eq!(I::min_value().checked_rem(&I::from(-1_i8)), None);
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn fixed_division_and_remainder_support_all_ownership_and_assignment_forms() {
        type I = FixedBigInt<4>;
        let left = I::from(-20_i8);
        let right = I::from(6_i8);
        assert_eq!(left / right, I::from(-3_i8));
        assert_eq!(left / &right, I::from(-3_i8));
        assert_eq!(&left / right, I::from(-3_i8));
        assert_eq!(&left / &right, I::from(-3_i8));
        assert_eq!(left % right, I::from(-2_i8));
        assert_eq!(left % &right, I::from(-2_i8));
        assert_eq!(&left % right, I::from(-2_i8));
        assert_eq!(&left % &right, I::from(-2_i8));

        let mut quotient = left;
        quotient /= right;
        assert_eq!(quotient, I::from(-3_i8));
        quotient = left;
        quotient /= &right;
        assert_eq!(quotient, I::from(-3_i8));
        let mut remainder = left;
        remainder %= right;
        assert_eq!(remainder, I::from(-2_i8));
        remainder = left;
        remainder %= &right;
        assert_eq!(remainder, I::from(-2_i8));
    }

    #[test]
    fn fixed_division_matches_i128_and_div_rem_trait() {
        type I = FixedBigInt<{ 128 / Word::BITS as usize }>;
        let lhs = I::from(-1_000_000_i64);
        let rhs = I::from(37_u8);
        assert_eq!((lhs / rhs).to_i128(), Some(-1_000_000 / 37));
        assert_eq!((lhs % rhs).to_i128(), Some(-1_000_000 % 37));
        assert_eq!(lhs.div_rem(&rhs), (lhs / rhs, lhs % rhs));
        assert_eq!(
            lhs.rem_euclid(&rhs),
            I::from((-1_000_000_i128).rem_euclid(37))
        );
    }

    #[test]
    fn divisor_wider_than_the_fixed_value_returns_zero_and_the_value() {
        let value = FixedBigInt::<1>::from(-7_i8);
        assert_eq!(value / u128::MAX, FixedBigInt::zero());
        assert_eq!(value % u128::MAX, value);
    }

    #[test]
    #[should_panic(expected = "attempted to divide by zero")]
    fn primitive_remainder_rejects_zero() {
        let _ = FixedBigInt::<1>::from(1_i8) % 0_u8;
    }

    #[test]
    #[should_panic(expected = "attempted to calculate remainder with zero")]
    fn fixed_euclidean_remainder_rejects_zero() {
        let _ = FixedBigInt::<2>::from(1_i8).rem_euclid(&FixedBigInt::zero());
    }
}
