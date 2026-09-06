//! Addition for [`BigInt`].

use alloc::vec::Vec;
use core::ops::{Add, AddAssign};

use crate::traits::{CheckedAdd, OverflowingAdd, SaturatingAdd, WrappingAdd};
use crate::{BigInt, Limb, Word};

impl Add<&BigInt> for &BigInt {
    type Output = BigInt;

    #[inline]
    fn add(self, rhs: &BigInt) -> Self::Output {
        let mut limbs = self.limbs.clone();
        add_assign_limbs(&mut limbs, &rhs.limbs);
        BigInt::from_limbs(limbs)
    }
}

impl Add<&BigInt> for BigInt {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Self) -> Self::Output {
        add_assign_limbs(&mut self.limbs, &rhs.limbs);
        Self::from_limbs(self.limbs)
    }
}

impl Add<BigInt> for &BigInt {
    type Output = BigInt;

    #[inline]
    fn add(self, mut rhs: BigInt) -> Self::Output {
        add_assign_limbs(&mut rhs.limbs, &self.limbs);
        BigInt::from_limbs(rhs.limbs)
    }
}

impl Add for BigInt {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        if self.limbs.capacity() >= rhs.limbs.capacity() {
            self + &rhs
        } else {
            &self + rhs
        }
    }
}

impl AddAssign<&BigInt> for BigInt {
    fn add_assign(&mut self, rhs: &BigInt) {
        add_assign_limbs(&mut self.limbs, &rhs.limbs);
        crate::encoding::normalize_signed(&mut self.limbs);
    }
}

impl AddAssign for BigInt {
    fn add_assign(&mut self, rhs: Self) {
        *self += &rhs;
    }
}

macro_rules! impl_add_unsigned_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl Add<$primitive> for BigInt {
                type Output = Self;

                #[inline]
                fn add(mut self, rhs: $primitive) -> Self::Output {
                    add_assign_u128(&mut self.limbs, rhs as u128);
                    Self::from_limbs(self.limbs)
                }
            }

            impl Add<$primitive> for &BigInt {
                type Output = BigInt;

                #[inline]
                fn add(self, rhs: $primitive) -> Self::Output {
                    self.clone() + rhs
                }
            }

            impl AddAssign<$primitive> for BigInt {
                #[inline]
                fn add_assign(&mut self, rhs: $primitive) {
                    add_assign_u128(&mut self.limbs, rhs as u128);
                    crate::encoding::normalize_signed(&mut self.limbs);
                }
            }
        )*
    };
}

impl_add_unsigned_primitive!(u8, u16, u32, u64, u128);

impl CheckedAdd for BigInt {
    fn checked_add(&self, rhs: &Self) -> Option<Self> {
        Some(self + rhs)
    }
}

impl OverflowingAdd for BigInt {
    fn overflowing_add(&self, rhs: &Self) -> (Self, bool) {
        (self + rhs, false)
    }
}

impl WrappingAdd for BigInt {
    fn wrapping_add(&self, rhs: &Self) -> Self {
        self + rhs
    }
}

impl SaturatingAdd for BigInt {
    fn saturating_add(&self, rhs: &Self) -> Self {
        self + rhs
    }
}

fn add_assign_limbs(lhs: &mut Vec<Limb>, rhs: &[Limb]) {
    let lhs_extension = sign_extension(lhs);
    let rhs_extension = sign_extension(rhs);
    let width = lhs.len().max(rhs.len()) + 1;
    lhs.resize(width, lhs_extension);

    let mut carry = Limb::new(0);
    for (index, left) in lhs.iter_mut().enumerate() {
        let right = rhs.get(index).copied().unwrap_or(rhs_extension);
        (*left, carry) = left.carrying_add(right, carry);
    }
}

fn sign_extension(limbs: &[Limb]) -> Limb {
    match limbs.last() {
        Some(limb) if limb.to_word() >> (Word::BITS - 1) != 0 => Limb::new(Word::MAX),
        _ => Limb::new(0),
    }
}

#[inline]
fn add_assign_u128(lhs: &mut Vec<Limb>, value: u128) {
    // Five limbs cover the four-word 32-bit representation plus a positive
    // sign limb. The 64-bit representation uses at most the first three.
    let mut words = [Limb::new(0); 5];

    #[cfg(target_pointer_width = "64")]
    {
        words[0] = Limb::new(value as Word);
        words[1] = Limb::new((value >> 64) as Word);
    }

    #[cfg(not(target_pointer_width = "64"))]
    {
        words[0] = Limb::new(value as Word);
        words[1] = Limb::new((value >> 32) as Word);
        words[2] = Limb::new((value >> 64) as Word);
        words[3] = Limb::new((value >> 96) as Word);
    }

    let mut used = words
        .iter()
        .rposition(|word| word.to_word() != 0)
        .map_or(0, |index| index + 1);
    if used != 0 && words[used - 1].to_word() >> (Word::BITS - 1) != 0 {
        used += 1;
    }
    add_assign_limbs(lhs, &words[..used]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn in_place_core_sign_extends_both_operands() {
        let mut positive = vec![Limb::new(Word::MAX >> 1)];
        add_assign_limbs(&mut positive, &[Limb::new(1)]);
        assert_eq!(
            BigInt::from_limbs(positive),
            BigInt::from(1_u8) << (Word::BITS - 1) as usize
        );

        let mut negative = vec![Limb::new(Word::MAX)];
        add_assign_limbs(&mut negative, &[Limb::new(1)]);
        assert!(BigInt::from_limbs(negative).is_zero());
    }

    #[test]
    fn bigint_addition_supports_all_ownership_and_assignment_forms() {
        let left = BigInt::from(-20_i8);
        let right = BigInt::from(6_i8);
        let expected = BigInt::from(-14_i8);
        assert_eq!(&left + &right, expected);
        assert_eq!(&left + right.clone(), expected);
        assert_eq!(left.clone() + &right, expected);
        assert_eq!(left.clone() + right.clone(), expected);

        let mut value = left;
        value += &right;
        assert_eq!(value, expected);
        value = BigInt::from(-20_i8);
        value += right;
        assert_eq!(value, expected);
    }

    #[test]
    fn unsigned_primitive_addition_supports_every_width_without_bigint_conversion() {
        assert_eq!(BigInt::from(-1_i8) + 2_u8, BigInt::from(1_i8));
        assert_eq!(&BigInt::from(-1_i8) + 2_u16, BigInt::from(1_i8));
        assert_eq!(BigInt::from(-1_i8) + 2_u32, BigInt::from(1_i8));
        assert_eq!(&BigInt::from(-1_i8) + 2_u64, BigInt::from(1_i8));
        assert_eq!(BigInt::from(-1_i8) + 2_u128, BigInt::from(1_i8));

        let mut value = BigInt::from(-1_i8);
        value += u8::MAX;
        value += u16::MAX;
        value += u32::MAX;
        value += u64::MAX;
        value += u128::MAX;
        let expected = BigInt::from(-1_i8)
            + BigInt::from(u8::MAX)
            + BigInt::from(u16::MAX)
            + BigInt::from(u32::MAX)
            + BigInt::from(u64::MAX)
            + BigInt::from(u128::MAX);
        assert_eq!(value, expected);
    }

    #[test]
    fn unbounded_signed_addition_traits_never_report_overflow() {
        let value = BigInt::from(i128::MAX);
        let one = BigInt::from(1_u8);
        let sum = BigInt::from(i128::MAX) + BigInt::from(1_u8);
        assert_eq!(value.checked_add(&one), Some(sum.clone()));
        assert_eq!(value.overflowing_add(&one), (sum.clone(), false));
        assert_eq!(value.wrapping_add(&one), sum.clone());
        assert_eq!(value.saturating_add(&one), sum);
    }
}
