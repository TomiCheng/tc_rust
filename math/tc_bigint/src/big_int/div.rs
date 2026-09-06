//! Division and remainder for [`BigInt`].

use core::ops::{Div, DivAssign, Rem, RemAssign};

use crate::traits::{CheckedDiv, CheckedRem, DivRem, RemEuclid};
use crate::{BigInt, Limb, Word, arithmetic};

impl BigInt {
    /// Returns the truncated quotient and remainder together.
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        Self::div_rem_ref(self, divisor)
    }

    /// Returns the least non-negative remainder modulo `divisor`.
    pub fn rem_euclid(&self, divisor: &Self) -> Self {
        assert!(
            !divisor.is_zero(),
            "attempted to calculate remainder with zero"
        );
        let remainder = self % divisor;
        if remainder.is_negative() {
            if divisor.is_negative() {
                &remainder - divisor
            } else {
                &remainder + divisor
            }
        } else {
            remainder
        }
    }

    fn div_rem_ref(lhs: &Self, rhs: &Self) -> (Self, Self) {
        let (lhs_negative, lhs_magnitude) = lhs.sign_magnitude();
        let (rhs_negative, rhs_magnitude) = rhs.sign_magnitude();
        let (quotient, remainder) = arithmetic::div_rem(&lhs_magnitude, &rhs_magnitude);
        (
            Self::from_sign_magnitude(lhs_negative != rhs_negative, quotient),
            Self::from_sign_magnitude(lhs_negative, remainder),
        )
    }

    fn div_ref(lhs: &Self, rhs: &Self) -> Self {
        Self::div_rem_ref(lhs, rhs).0
    }

    fn rem_ref(lhs: &Self, rhs: &Self) -> Self {
        Self::div_rem_ref(lhs, rhs).1
    }
}

macro_rules! impl_division_operator {
    ($trait:ident, $method:ident, $function:ident, $lhs:ty, $rhs:ty) => {
        impl $trait<$rhs> for $lhs {
            type Output = BigInt;

            fn $method(self, rhs: $rhs) -> Self::Output {
                BigInt::$function(&self, &rhs)
            }
        }
    };
}

impl_division_operator!(Div, div, div_ref, &BigInt, &BigInt);
impl_division_operator!(Div, div, div_ref, &BigInt, BigInt);
impl_division_operator!(Div, div, div_ref, BigInt, &BigInt);
impl_division_operator!(Div, div, div_ref, BigInt, BigInt);
impl_division_operator!(Rem, rem, rem_ref, &BigInt, &BigInt);
impl_division_operator!(Rem, rem, rem_ref, &BigInt, BigInt);
impl_division_operator!(Rem, rem, rem_ref, BigInt, &BigInt);
impl_division_operator!(Rem, rem, rem_ref, BigInt, BigInt);

impl DivAssign<&BigInt> for BigInt {
    fn div_assign(&mut self, rhs: &BigInt) {
        *self = &*self / rhs;
    }
}

impl DivAssign for BigInt {
    fn div_assign(&mut self, rhs: Self) {
        *self /= &rhs;
    }
}

impl RemAssign<&BigInt> for BigInt {
    fn rem_assign(&mut self, rhs: &BigInt) {
        *self = &*self % rhs;
    }
}

impl RemAssign for BigInt {
    fn rem_assign(&mut self, rhs: Self) {
        *self %= &rhs;
    }
}

macro_rules! impl_division_unsigned_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl Div<$primitive> for BigInt {
                type Output = Self;

                fn div(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(&self, rhs as u128).0
                }
            }

            impl Div<$primitive> for &BigInt {
                type Output = BigInt;

                fn div(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(self, rhs as u128).0
                }
            }

            impl Rem<$primitive> for BigInt {
                type Output = Self;

                fn rem(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(&self, rhs as u128).1
                }
            }

            impl Rem<$primitive> for &BigInt {
                type Output = BigInt;

                fn rem(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(self, rhs as u128).1
                }
            }

            impl DivAssign<$primitive> for BigInt {
                fn div_assign(&mut self, rhs: $primitive) {
                    *self = div_rem_u128(self, rhs as u128).0;
                }
            }

            impl RemAssign<$primitive> for BigInt {
                fn rem_assign(&mut self, rhs: $primitive) {
                    *self = div_rem_u128(self, rhs as u128).1;
                }
            }
        )*
    };
}

impl_division_unsigned_primitive!(u8, u16, u32, u64, u128);

impl DivRem for BigInt {
    type Quotient = Self;
    type Remainder = Self;

    fn div_rem(&self, rhs: &Self) -> (Self::Quotient, Self::Remainder) {
        BigInt::div_rem(self, rhs)
    }
}

impl RemEuclid for BigInt {
    type Output = Self;

    fn rem_euclid(&self, rhs: &Self) -> Self::Output {
        BigInt::rem_euclid(self, rhs)
    }
}

impl CheckedDiv for BigInt {
    fn checked_div(&self, rhs: &Self) -> Option<Self> {
        (!rhs.is_zero()).then(|| self.div_rem(rhs).0)
    }
}

impl CheckedRem for BigInt {
    fn checked_rem(&self, rhs: &Self) -> Option<Self> {
        (!rhs.is_zero()).then(|| self.div_rem(rhs).1)
    }
}

fn div_rem_u128(value: &BigInt, divisor: u128) -> (BigInt, BigInt) {
    assert!(divisor != 0, "attempted to divide by zero");
    let (negative, magnitude) = value.sign_magnitude();

    #[cfg(target_pointer_width = "64")]
    let divisor_limbs = [Limb::new(divisor as Word), Limb::new((divisor >> 64) as Word)];

    #[cfg(not(target_pointer_width = "64"))]
    let divisor_limbs = [
        Limb::new(divisor as Word),
        Limb::new((divisor >> 32) as Word),
        Limb::new((divisor >> 64) as Word),
        Limb::new((divisor >> 96) as Word),
    ];

    let used = divisor_limbs
        .iter()
        .rposition(|word| word.to_word() != 0)
        .map_or(0, |index| index + 1);
    let (quotient, remainder) = arithmetic::div_rem(&magnitude, &divisor_limbs[..used]);
    (
        BigInt::from_sign_magnitude(negative, quotient),
        BigInt::from_sign_magnitude(negative, remainder),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_division_remainder_and_assignment_support_every_width() {
        let value = BigInt::from(-120_i8);
        assert_eq!(value.clone() / 2_u8, BigInt::from(-60_i8));
        assert_eq!(&value / 3_u16, BigInt::from(-40_i8));
        assert_eq!(value.clone() / 4_u32, BigInt::from(-30_i8));
        assert_eq!(&value / 5_u64, BigInt::from(-24_i8));
        assert_eq!((-BigInt::from(u128::MAX)) / u128::MAX, BigInt::from(-1_i8));

        assert_eq!(value.clone() % 7_u8, BigInt::from(-1_i8));
        assert_eq!(&value % 11_u16, BigInt::from(-10_i8));
        assert_eq!(value.clone() % 13_u32, BigInt::from(-3_i8));
        assert_eq!(&value % 17_u64, BigInt::from(-1_i8));
        assert_eq!((-BigInt::from(u128::MAX)) % u128::MAX, BigInt::default());

        let mut quotient = BigInt::from(-120_i8);
        quotient /= 3_u8;
        quotient /= 2_u16;
        quotient /= 2_u32;
        quotient /= 2_u64;
        quotient /= 5_u128;
        assert_eq!(quotient, BigInt::from(-1_i8));

        let mut remainder = BigInt::from(-120_i8);
        remainder %= 17_u8;
        remainder %= 7_u16;
        remainder %= 5_u32;
        remainder %= 3_u64;
        remainder %= 2_u128;
        assert_eq!(remainder, BigInt::from(-1_i8));
    }

    #[test]
    fn bigint_division_and_remainder_support_all_ownership_and_assignment_forms() {
        let left = BigInt::from(-20_i8);
        let right = BigInt::from(6_i8);
        assert_eq!(&left / &right, BigInt::from(-3_i8));
        assert_eq!(&left / right.clone(), BigInt::from(-3_i8));
        assert_eq!(left.clone() / &right, BigInt::from(-3_i8));
        assert_eq!(left.clone() / right.clone(), BigInt::from(-3_i8));
        assert_eq!(&left % &right, BigInt::from(-2_i8));
        assert_eq!(&left % right.clone(), BigInt::from(-2_i8));
        assert_eq!(left.clone() % &right, BigInt::from(-2_i8));
        assert_eq!(left.clone() % right.clone(), BigInt::from(-2_i8));

        let mut quotient = left.clone();
        quotient /= &right;
        assert_eq!(quotient, BigInt::from(-3_i8));
        quotient = left.clone();
        quotient /= right.clone();
        assert_eq!(quotient, BigInt::from(-3_i8));
        let mut remainder = left.clone();
        remainder %= &right;
        assert_eq!(remainder, BigInt::from(-2_i8));
        remainder = left;
        remainder %= right;
        assert_eq!(remainder, BigInt::from(-2_i8));
    }

    #[test]
    #[should_panic(expected = "attempted to divide by zero")]
    fn primitive_remainder_rejects_zero() {
        let _ = BigInt::from(1_i8) % 0_u8;
    }

    #[test]
    #[should_panic(expected = "attempted to calculate remainder with zero")]
    fn euclidean_remainder_rejects_zero() {
        let _ = BigInt::from(1_i8).rem_euclid(&BigInt::default());
    }
}
