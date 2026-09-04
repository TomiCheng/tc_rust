//! Addition for [`BigUint`].

use alloc::vec::Vec;
use core::ops::{Add, AddAssign};

use crate::traits::{CheckedAdd, OverflowingAdd, SaturatingAdd, WrappingAdd};
use crate::{BigUint, Limb, Word};

impl Add<&BigUint> for &BigUint {
    type Output = BigUint;

    #[inline]
    fn add(self, rhs: &BigUint) -> Self::Output {
        let mut limbs = self.limbs.clone();
        add_assign_limbs(&mut limbs, &rhs.limbs);
        BigUint::from_limbs(limbs)
    }
}

impl Add<&BigUint> for BigUint {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Self) -> Self::Output {
        add_assign_limbs(&mut self.limbs, &rhs.limbs);
        Self::from_limbs(self.limbs)
    }
}

impl Add<BigUint> for &BigUint {
    type Output = BigUint;

    #[inline]
    fn add(self, mut rhs: BigUint) -> Self::Output {
        add_assign_limbs(&mut rhs.limbs, &self.limbs);
        BigUint::from_limbs(rhs.limbs)
    }
}

impl Add for BigUint {
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

impl AddAssign<&BigUint> for BigUint {
    fn add_assign(&mut self, rhs: &BigUint) {
        add_assign_limbs(&mut self.limbs, &rhs.limbs);
    }
}

impl AddAssign for BigUint {
    fn add_assign(&mut self, rhs: Self) {
        *self += &rhs;
    }
}

macro_rules! impl_add_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl Add<$primitive> for BigUint {
                type Output = Self;

                #[inline]
                fn add(mut self, rhs: $primitive) -> Self::Output {
                    add_assign_u128(&mut self.limbs, rhs as u128);
                    Self::from_limbs(self.limbs)
                }
            }

            impl Add<$primitive> for &BigUint {
                type Output = BigUint;

                #[inline]
                fn add(self, rhs: $primitive) -> Self::Output {
                    self.clone() + rhs
                }
            }

            impl AddAssign<$primitive> for BigUint {
                #[inline]
                fn add_assign(&mut self, rhs: $primitive) {
                    add_assign_u128(&mut self.limbs, rhs as u128);
                }
            }
        )*
    };
}

impl_add_primitive!(u8, u16, u32, u64, u128);

impl CheckedAdd for BigUint {
    fn checked_add(&self, rhs: &Self) -> Option<Self> {
        Some(self + rhs)
    }
}

impl OverflowingAdd for BigUint {
    fn overflowing_add(&self, rhs: &Self) -> (Self, bool) {
        (self + rhs, false)
    }
}

impl WrappingAdd for BigUint {
    fn wrapping_add(&self, rhs: &Self) -> Self {
        self + rhs
    }
}

impl SaturatingAdd for BigUint {
    fn saturating_add(&self, rhs: &Self) -> Self {
        self + rhs
    }
}

fn add_assign_limbs(lhs: &mut Vec<Limb>, rhs: &[Limb]) {
    if lhs.len() < rhs.len() {
        lhs.resize(rhs.len(), Limb(0));
    }

    let mut carry = Limb(0);
    for (left, right) in lhs.iter_mut().zip(rhs.iter().copied()) {
        (*left, carry) = left.carrying_add(right, carry);
    }
    for left in lhs.iter_mut().skip(rhs.len()) {
        if carry.0 == 0 {
            break;
        }
        (*left, carry) = left.carrying_add(Limb(0), carry);
    }
    if carry.0 != 0 {
        lhs.push(carry);
    }
}

#[inline]
fn add_assign_u128(lhs: &mut Vec<Limb>, value: u128) {
    #[cfg(target_pointer_width = "64")]
    let words = [Limb(value as Word), Limb((value >> 64) as Word)];

    #[cfg(not(target_pointer_width = "64"))]
    let words = [
        Limb(value as Word),
        Limb((value >> 32) as Word),
        Limb((value >> 64) as Word),
        Limb((value >> 96) as Word),
    ];

    let used = words
        .iter()
        .rposition(|word| word.0 != 0)
        .map_or(0, |index| index + 1);
    add_assign_limbs(lhs, &words[..used]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn in_place_core_grows_and_propagates_carry() {
        let mut lhs = vec![Limb(Word::MAX), Limb(Word::MAX)];
        add_assign_limbs(&mut lhs, &[Limb(1)]);
        assert_eq!(lhs, [Limb(0), Limb(0), Limb(1)]);
    }

    #[test]
    fn bigint_addition_supports_all_ownership_and_assignment_forms() {
        let left = BigUint::from(20_u8);
        let right = BigUint::from(6_u8);
        let expected = BigUint::from(26_u8);
        assert_eq!(&left + &right, expected);
        assert_eq!(&left + right.clone(), expected);
        assert_eq!(left.clone() + &right, expected);
        assert_eq!(left.clone() + right.clone(), expected);

        let mut value = left;
        value += &right;
        assert_eq!(value, expected);
        value = BigUint::from(20_u8);
        value += right;
        assert_eq!(value, expected);
    }

    #[test]
    fn primitive_addition_is_direct_and_supports_every_unsigned_width() {
        assert_eq!((BigUint::from(1_u8) + 2_u8), BigUint::from(3_u8));
        assert_eq!((&BigUint::from(1_u8) + 2_u16), BigUint::from(3_u8));
        assert_eq!((BigUint::from(1_u8) + 2_u32), BigUint::from(3_u8));
        assert_eq!((&BigUint::from(1_u8) + 2_u64), BigUint::from(3_u8));
        assert_eq!((BigUint::from(1_u8) + 2_u128), BigUint::from(3_u8));

        let mut value = BigUint::from(1_u8);
        value += u8::MAX;
        value += u16::MAX;
        value += u32::MAX;
        value += u64::MAX;
        value += u128::MAX;
        let expected = BigUint::from(1_u8)
            + BigUint::from(u8::MAX)
            + BigUint::from(u16::MAX)
            + BigUint::from(u32::MAX)
            + BigUint::from(u64::MAX)
            + BigUint::from(u128::MAX);
        assert_eq!(value, expected);
    }

    #[test]
    fn primitive_u128_addition_propagates_beyond_its_source_width() {
        assert_eq!(BigUint::from(u128::MAX) + 1_u8, BigUint::from(1_u8) << 128);
    }

    #[test]
    fn unbounded_addition_traits_never_report_overflow() {
        let value = BigUint::from(u128::MAX);
        let one = BigUint::from(1_u8);
        let sum = BigUint::from(1_u8) << 128;
        assert_eq!(value.checked_add(&one), Some(sum.clone()));
        assert_eq!(value.overflowing_add(&one), (sum.clone(), false));
        assert_eq!(value.wrapping_add(&one), sum);
        assert_eq!(value.saturating_add(&one), BigUint::from(1_u8) << 128);
    }
}
