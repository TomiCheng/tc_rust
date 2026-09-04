//! Division and remainder for [`BigUint`].

use core::ops::{Div, DivAssign, Rem, RemAssign};

use crate::traits::{CheckedDiv, CheckedRem, DivRem, RemEuclid};
use crate::{BigUint, Limb, Word, arithmetic};

impl BigUint {
    /// Returns the quotient and remainder together.
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        let (quotient, remainder) = arithmetic::div_rem(&self.limbs, &divisor.limbs);
        (Self::from_limbs(quotient), Self::from_limbs(remainder))
    }

    /// Returns the Euclidean remainder.
    pub fn rem_euclid(&self, divisor: &Self) -> Self {
        self % divisor
    }

    fn div_ref(lhs: &Self, rhs: &Self) -> Self {
        lhs.div_rem(rhs).0
    }

    fn rem_ref(lhs: &Self, rhs: &Self) -> Self {
        lhs.div_rem(rhs).1
    }
}

macro_rules! impl_division_operator {
    ($trait:ident, $method:ident, $function:ident, $lhs:ty, $rhs:ty) => {
        impl $trait<$rhs> for $lhs {
            type Output = BigUint;

            fn $method(self, rhs: $rhs) -> Self::Output {
                BigUint::$function(&self, &rhs)
            }
        }
    };
}

impl_division_operator!(Div, div, div_ref, &BigUint, &BigUint);
impl_division_operator!(Div, div, div_ref, &BigUint, BigUint);
impl_division_operator!(Div, div, div_ref, BigUint, &BigUint);
impl_division_operator!(Div, div, div_ref, BigUint, BigUint);
impl_division_operator!(Rem, rem, rem_ref, &BigUint, &BigUint);
impl_division_operator!(Rem, rem, rem_ref, &BigUint, BigUint);
impl_division_operator!(Rem, rem, rem_ref, BigUint, &BigUint);
impl_division_operator!(Rem, rem, rem_ref, BigUint, BigUint);

impl DivAssign<&BigUint> for BigUint {
    fn div_assign(&mut self, rhs: &BigUint) {
        *self = &*self / rhs;
    }
}

impl DivAssign for BigUint {
    fn div_assign(&mut self, rhs: Self) {
        *self /= &rhs;
    }
}

impl RemAssign<&BigUint> for BigUint {
    fn rem_assign(&mut self, rhs: &BigUint) {
        *self = &*self % rhs;
    }
}

impl RemAssign for BigUint {
    fn rem_assign(&mut self, rhs: Self) {
        *self %= &rhs;
    }
}

macro_rules! impl_division_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl Div<$primitive> for BigUint {
                type Output = Self;

                fn div(mut self, rhs: $primitive) -> Self::Output {
                    div_assign_u128(&mut self, rhs as u128);
                    self
                }
            }

            impl Div<$primitive> for &BigUint {
                type Output = BigUint;

                fn div(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(self, rhs as u128).0
                }
            }

            impl Rem<$primitive> for BigUint {
                type Output = Self;

                fn rem(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(&self, rhs as u128).1
                }
            }

            impl Rem<$primitive> for &BigUint {
                type Output = BigUint;

                fn rem(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(self, rhs as u128).1
                }
            }

            impl DivAssign<$primitive> for BigUint {
                fn div_assign(&mut self, rhs: $primitive) {
                    div_assign_u128(self, rhs as u128);
                }
            }

            impl RemAssign<$primitive> for BigUint {
                fn rem_assign(&mut self, rhs: $primitive) {
                    *self = div_rem_u128(self, rhs as u128).1;
                }
            }
        )*
    };
}

impl_division_primitive!(u8, u16, u32, u64, u128);

impl DivRem for BigUint {
    type Quotient = Self;
    type Remainder = Self;

    fn div_rem(&self, rhs: &Self) -> (Self::Quotient, Self::Remainder) {
        BigUint::div_rem(self, rhs)
    }
}

impl RemEuclid for BigUint {
    type Output = Self;

    fn rem_euclid(&self, rhs: &Self) -> Self::Output {
        BigUint::rem_euclid(self, rhs)
    }
}

impl CheckedDiv for BigUint {
    fn checked_div(&self, rhs: &Self) -> Option<Self> {
        (!rhs.is_zero()).then(|| self.div_rem(rhs).0)
    }
}

impl CheckedRem for BigUint {
    fn checked_rem(&self, rhs: &Self) -> Option<Self> {
        (!rhs.is_zero()).then(|| self.div_rem(rhs).1)
    }
}

fn div_assign_u128(value: &mut BigUint, divisor: u128) {
    assert!(divisor != 0, "attempted to divide by zero");
    if divisor <= Word::MAX as u128 {
        let _remainder = arithmetic::div_rem_small(&mut value.limbs, divisor as Word);
        arithmetic::normalize(&mut value.limbs);
        return;
    }

    let (quotient, _remainder) = div_rem_u128(value, divisor);
    value.limbs = quotient.limbs;
}

fn div_rem_u128(value: &BigUint, divisor: u128) -> (BigUint, BigUint) {
    assert!(divisor != 0, "attempted to divide by zero");

    #[cfg(target_pointer_width = "64")]
    let divisor_limbs = [Limb(divisor as Word), Limb((divisor >> 64) as Word)];

    #[cfg(not(target_pointer_width = "64"))]
    let divisor_limbs = [
        Limb(divisor as Word),
        Limb((divisor >> 32) as Word),
        Limb((divisor >> 64) as Word),
        Limb((divisor >> 96) as Word),
    ];

    let used = divisor_limbs
        .iter()
        .rposition(|word| word.0 != 0)
        .map_or(0, |index| index + 1);
    let (quotient, remainder) = arithmetic::div_rem(&value.limbs, &divisor_limbs[..used]);
    (
        BigUint::from_limbs(quotient),
        BigUint::from_limbs(remainder),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_division_remainder_and_assignment_support_every_width() {
        let value = BigUint::from(120_u8);
        assert_eq!(value.clone() / 2_u8, BigUint::from(60_u8));
        assert_eq!(&value / 3_u16, BigUint::from(40_u8));
        assert_eq!(value.clone() / 4_u32, BigUint::from(30_u8));
        assert_eq!(&value / 5_u64, BigUint::from(24_u8));
        assert_eq!(BigUint::from(u128::MAX) / u128::MAX, BigUint::from(1_u8));

        assert_eq!(value.clone() % 7_u8, BigUint::from(1_u8));
        assert_eq!(&value % 11_u16, BigUint::from(10_u8));
        assert_eq!(value.clone() % 13_u32, BigUint::from(3_u8));
        assert_eq!(&value % 17_u64, BigUint::from(1_u8));
        assert_eq!(BigUint::from(u128::MAX) % u128::MAX, BigUint::default());

        let mut quotient = BigUint::from(120_u8);
        quotient /= 3_u8;
        quotient /= 2_u16;
        quotient /= 2_u32;
        quotient /= 2_u64;
        quotient /= 5_u128;
        assert_eq!(quotient, BigUint::from(1_u8));

        let mut remainder = BigUint::from(120_u8);
        remainder %= 17_u8;
        remainder %= 7_u16;
        remainder %= 5_u32;
        remainder %= 3_u64;
        remainder %= 2_u128;
        assert_eq!(remainder, BigUint::from(1_u8));
    }

    #[test]
    fn bigint_division_and_remainder_support_all_ownership_and_assignment_forms() {
        let left = BigUint::from(20_u8);
        let right = BigUint::from(6_u8);
        assert_eq!(&left / &right, BigUint::from(3_u8));
        assert_eq!(&left / right.clone(), BigUint::from(3_u8));
        assert_eq!(left.clone() / &right, BigUint::from(3_u8));
        assert_eq!(left.clone() / right.clone(), BigUint::from(3_u8));
        assert_eq!(&left % &right, BigUint::from(2_u8));
        assert_eq!(&left % right.clone(), BigUint::from(2_u8));
        assert_eq!(left.clone() % &right, BigUint::from(2_u8));
        assert_eq!(left.clone() % right.clone(), BigUint::from(2_u8));

        let mut quotient = left.clone();
        quotient /= &right;
        assert_eq!(quotient, BigUint::from(3_u8));
        quotient = left.clone();
        quotient /= right.clone();
        assert_eq!(quotient, BigUint::from(3_u8));
        let mut remainder = left.clone();
        remainder %= &right;
        assert_eq!(remainder, BigUint::from(2_u8));
        remainder = left;
        remainder %= right;
        assert_eq!(remainder, BigUint::from(2_u8));
    }

    #[test]
    fn large_division_round_trips() {
        let dividend = BigUint::from_le_u64(&[u64::MAX, 0x1234_5678_9abc_def0]);
        let divisor = BigUint::from(97_u8);
        let (quotient, remainder) = dividend.div_rem(&divisor);
        assert_eq!(&quotient * &divisor + remainder, dividend);
    }

    #[test]
    #[should_panic(expected = "attempted to divide by zero")]
    fn primitive_division_rejects_zero() {
        let _ = BigUint::from(1_u8) / 0_u8;
    }
}
