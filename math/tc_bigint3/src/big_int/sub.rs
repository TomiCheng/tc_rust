//! Subtraction for [`BigInt`].

use alloc::vec::Vec;
use core::ops::{Sub, SubAssign};

use crate::traits::CheckedSub;
use crate::{BigInt, Limb, Word};

impl BigInt {
    fn sub_ref(lhs: &Self, rhs: &Self) -> Self {
        lhs + &Self::neg_ref(rhs)
    }
}

macro_rules! impl_sub {
    ($lhs:ty, $rhs:ty) => {
        impl Sub<$rhs> for $lhs {
            type Output = BigInt;

            fn sub(self, rhs: $rhs) -> Self::Output {
                BigInt::sub_ref(&self, &rhs)
            }
        }
    };
}

impl_sub!(&BigInt, &BigInt);
impl_sub!(&BigInt, BigInt);
impl_sub!(BigInt, &BigInt);
impl_sub!(BigInt, BigInt);

impl SubAssign<&BigInt> for BigInt {
    fn sub_assign(&mut self, rhs: &BigInt) {
        *self = &*self - rhs;
    }
}

impl SubAssign for BigInt {
    fn sub_assign(&mut self, rhs: Self) {
        *self -= &rhs;
    }
}

macro_rules! impl_sub_unsigned_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl Sub<$primitive> for BigInt {
                type Output = Self;

                fn sub(mut self, rhs: $primitive) -> Self::Output {
                    sub_assign_u128(&mut self.limbs, rhs as u128);
                    Self::from_limbs(self.limbs)
                }
            }

            impl Sub<$primitive> for &BigInt {
                type Output = BigInt;

                fn sub(self, rhs: $primitive) -> Self::Output {
                    self.clone() - rhs
                }
            }

            impl SubAssign<$primitive> for BigInt {
                fn sub_assign(&mut self, rhs: $primitive) {
                    sub_assign_u128(&mut self.limbs, rhs as u128);
                    crate::encoding::normalize_signed(&mut self.limbs);
                }
            }
        )*
    };
}

impl_sub_unsigned_primitive!(u8, u16, u32, u64, u128);

impl CheckedSub for BigInt {
    fn checked_sub(&self, rhs: &Self) -> Option<Self> {
        Some(self - rhs)
    }
}

fn sub_assign_u128(lhs: &mut Vec<Limb>, rhs: u128) {
    let lhs_extension = match lhs.last() {
        Some(word) if word.0 >> (Word::BITS - 1) != 0 => Limb(Word::MAX),
        _ => Limb(0),
    };

    #[cfg(target_pointer_width = "64")]
    let words = [Limb(rhs as Word), Limb((rhs >> 64) as Word), Limb(0)];

    #[cfg(not(target_pointer_width = "64"))]
    let words = [
        Limb(rhs as Word),
        Limb((rhs >> 32) as Word),
        Limb((rhs >> 64) as Word),
        Limb((rhs >> 96) as Word),
        Limb(0),
    ];

    let mut rhs_len = words.len() - 1;
    while rhs_len != 0 && words[rhs_len - 1].0 == 0 {
        rhs_len -= 1;
    }
    if rhs_len != 0 && words[rhs_len - 1].0 >> (Word::BITS - 1) != 0 {
        rhs_len += 1;
    }

    let width = lhs.len().max(rhs_len) + 1;
    lhs.resize(width, lhs_extension);
    let mut borrow = Limb(0);
    for (index, left) in lhs.iter_mut().enumerate() {
        let right = words.get(index).copied().unwrap_or_default();
        (*left, borrow) = left.borrowing_sub(right, borrow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_subtraction_and_assignment_support_every_width() {
        assert_eq!(BigInt::from(10_i8) - 1_u8, BigInt::from(9_i8));
        assert_eq!(&BigInt::from(10_i8) - 2_u16, BigInt::from(8_i8));
        assert_eq!(BigInt::from(10_i8) - 3_u32, BigInt::from(7_i8));
        assert_eq!(&BigInt::from(10_i8) - 4_u64, BigInt::from(6_i8));
        assert_eq!(BigInt::default() - u128::MAX, -BigInt::from(u128::MAX));

        let mut value = BigInt::from(100_i16);
        value -= 1_u8;
        value -= 2_u16;
        value -= 3_u32;
        value -= 4_u64;
        value -= 5_u128;
        assert_eq!(value, BigInt::from(85_i8));
    }

    #[test]
    fn bigint_subtraction_supports_all_ownership_and_assignment_forms() {
        let left = BigInt::from(-20_i8);
        let right = BigInt::from(6_i8);
        let expected = BigInt::from(-26_i8);
        assert_eq!(&left - &right, expected);
        assert_eq!(&left - right.clone(), expected);
        assert_eq!(left.clone() - &right, expected);
        assert_eq!(left.clone() - right.clone(), expected);

        let mut value = left;
        value -= &right;
        assert_eq!(value, expected);
        value = BigInt::from(-20_i8);
        value -= right;
        assert_eq!(value, expected);
    }

    #[test]
    fn checked_sub_never_overflows_for_dynamic_signed_values() {
        assert_eq!(
            BigInt::from(i128::MIN).checked_sub(&BigInt::from(u128::MAX)),
            Some(BigInt::from(i128::MIN) - BigInt::from(u128::MAX))
        );
    }
}
