//! Multiplication for [`BigUint`].

use core::ops::{Mul, MulAssign};

use crate::traits::{CheckedMul, OverflowingMul, SaturatingMul, Square, WrappingMul};
use crate::{BigUint, Limb, WideWord, Word, limb::slice};

impl BigUint {
    /// Returns `self * self`.
    pub fn square(&self) -> Self {
        Self::from_limbs(slice::square(&self.limbs))
    }

    fn mul_ref(lhs: &Self, rhs: &Self) -> Self {
        Self::from_limbs(slice::mul(&lhs.limbs, &rhs.limbs))
    }
}

macro_rules! impl_mul {
    ($lhs:ty, $rhs:ty) => {
        impl Mul<$rhs> for $lhs {
            type Output = BigUint;

            fn mul(self, rhs: $rhs) -> Self::Output {
                BigUint::mul_ref(&self, &rhs)
            }
        }
    };
}

impl_mul!(&BigUint, &BigUint);
impl_mul!(&BigUint, BigUint);
impl_mul!(BigUint, &BigUint);
impl_mul!(BigUint, BigUint);

impl MulAssign<&BigUint> for BigUint {
    fn mul_assign(&mut self, rhs: &BigUint) {
        *self = &*self * rhs;
    }
}

impl MulAssign for BigUint {
    fn mul_assign(&mut self, rhs: Self) {
        *self *= &rhs;
    }
}

macro_rules! impl_mul_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl Mul<$primitive> for BigUint {
                type Output = Self;

                fn mul(mut self, rhs: $primitive) -> Self::Output {
                    mul_assign_u128(&mut self.limbs, rhs as u128);
                    Self::from_limbs(self.limbs)
                }
            }

            impl Mul<$primitive> for &BigUint {
                type Output = BigUint;

                fn mul(self, rhs: $primitive) -> Self::Output {
                    self.clone() * rhs
                }
            }

            impl MulAssign<$primitive> for BigUint {
                fn mul_assign(&mut self, rhs: $primitive) {
                    mul_assign_u128(&mut self.limbs, rhs as u128);
                    slice::normalize(&mut self.limbs);
                }
            }
        )*
    };
}

impl_mul_primitive!(u8, u16, u32, u64, u128);

impl Square for BigUint {
    type Output = Self;

    fn square(&self) -> Self::Output {
        BigUint::square(self)
    }
}

impl CheckedMul for BigUint {
    fn checked_mul(&self, rhs: &Self) -> Option<Self> {
        Some(self * rhs)
    }
}

impl OverflowingMul for BigUint {
    fn overflowing_mul(&self, rhs: &Self) -> (Self, bool) {
        (self * rhs, false)
    }
}

impl WrappingMul for BigUint {
    fn wrapping_mul(&self, rhs: &Self) -> Self {
        self * rhs
    }
}

impl SaturatingMul for BigUint {
    fn saturating_mul(&self, rhs: &Self) -> Self {
        self * rhs
    }
}

fn mul_assign_u128(lhs: &mut alloc::vec::Vec<Limb>, rhs: u128) {
    if rhs == 0 || lhs.is_empty() {
        lhs.clear();
        return;
    }

    if rhs <= Word::MAX as u128 {
        let mut carry = 0 as Word;
        for limb in lhs.iter_mut() {
            let product = limb.to_word() as WideWord * rhs as WideWord + carry as WideWord;
            *limb = Limb::new(product as Word);
            carry = (product >> Word::BITS) as Word;
        }
        if carry != 0 {
            lhs.push(Limb::new(carry));
        }
        return;
    }

    #[cfg(target_pointer_width = "64")]
    let words = [Limb::new(rhs as Word), Limb::new((rhs >> 64) as Word)];

    #[cfg(not(target_pointer_width = "64"))]
    let words = [
        Limb::new(rhs as Word),
        Limb::new((rhs >> 32) as Word),
        Limb::new((rhs >> 64) as Word),
        Limb::new((rhs >> 96) as Word),
    ];

    let used = words
        .iter()
        .rposition(|word| word.to_word() != 0)
        .map_or(0, |index| index + 1);
    *lhs = slice::mul(lhs, &words[..used]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_multiplication_and_assignment_support_every_width() {
        assert_eq!(BigUint::from(3_u8) * 2_u8, BigUint::from(6_u8));
        assert_eq!(&BigUint::from(3_u8) * 3_u16, BigUint::from(9_u8));
        assert_eq!(BigUint::from(3_u8) * 4_u32, BigUint::from(12_u8));
        assert_eq!(&BigUint::from(3_u8) * 5_u64, BigUint::from(15_u8));
        assert_eq!(
            BigUint::from(3_u8) * u128::MAX,
            BigUint::from(u128::MAX) * BigUint::from(3_u8)
        );

        let mut value = BigUint::from(2_u8);
        value *= 2_u8;
        value *= 3_u16;
        value *= 4_u32;
        value *= 5_u64;
        value *= 6_u128;
        assert_eq!(value, BigUint::from(1_440_u16));
    }

    #[test]
    fn bigint_multiplication_supports_all_ownership_and_assignment_forms() {
        let left = BigUint::from(20_u8);
        let right = BigUint::from(6_u8);
        let expected = BigUint::from(120_u8);
        assert_eq!(&left * &right, expected);
        assert_eq!(&left * right.clone(), expected);
        assert_eq!(left.clone() * &right, expected);
        assert_eq!(left.clone() * right.clone(), expected);

        let mut value = left;
        value *= &right;
        assert_eq!(value, expected);
        value = BigUint::from(20_u8);
        value *= right;
        assert_eq!(value, expected);
    }

    #[test]
    fn multiplying_by_a_word_reuses_owned_storage() {
        let mut value = BigUint::from(u128::MAX);
        value.limbs.reserve(8);
        let pointer = value.limbs.as_ptr();
        let result = value * 2_u8;
        assert_eq!(result.limbs.as_ptr(), pointer);
    }
}
