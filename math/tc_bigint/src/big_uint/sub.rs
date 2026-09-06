//! Subtraction for [`BigUint`].

use alloc::vec::Vec;
use core::cmp::Ordering;
use core::ops::{Sub, SubAssign};

use crate::traits::{CheckedSub, SaturatingSub};
use crate::{BigUint, Limb, Word, arithmetic};

impl Sub<&BigUint> for &BigUint {
    type Output = BigUint;

    fn sub(self, rhs: &BigUint) -> Self::Output {
        self.checked_sub(rhs)
            .expect("attempted to subtract with underflow")
    }
}

impl Sub<&BigUint> for BigUint {
    type Output = Self;

    fn sub(mut self, rhs: &BigUint) -> Self::Output {
        assert!(
            sub_assign_limbs(&mut self.limbs, &rhs.limbs),
            "attempted to subtract with underflow"
        );
        Self::from_limbs(self.limbs)
    }
}

impl Sub<BigUint> for &BigUint {
    type Output = BigUint;

    fn sub(self, mut rhs: BigUint) -> Self::Output {
        assert!(
            sub_into_rhs(&self.limbs, &mut rhs.limbs),
            "attempted to subtract with underflow"
        );
        BigUint::from_limbs(rhs.limbs)
    }
}

impl Sub for BigUint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        if self.limbs.capacity() >= rhs.limbs.capacity() {
            self - &rhs
        } else {
            &self - rhs
        }
    }
}

impl SubAssign<&BigUint> for BigUint {
    fn sub_assign(&mut self, rhs: &BigUint) {
        assert!(
            sub_assign_limbs(&mut self.limbs, &rhs.limbs),
            "attempted to subtract with underflow"
        );
    }
}

impl SubAssign for BigUint {
    fn sub_assign(&mut self, rhs: Self) {
        *self -= &rhs;
    }
}

macro_rules! impl_sub_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl Sub<$primitive> for BigUint {
                type Output = Self;

                fn sub(mut self, rhs: $primitive) -> Self::Output {
                    assert!(
                        sub_assign_u128(&mut self.limbs, rhs as u128),
                        "attempted to subtract with underflow"
                    );
                    Self::from_limbs(self.limbs)
                }
            }

            impl Sub<$primitive> for &BigUint {
                type Output = BigUint;

                fn sub(self, rhs: $primitive) -> Self::Output {
                    self.clone() - rhs
                }
            }

            impl SubAssign<$primitive> for BigUint {
                fn sub_assign(&mut self, rhs: $primitive) {
                    assert!(
                        sub_assign_u128(&mut self.limbs, rhs as u128),
                        "attempted to subtract with underflow"
                    );
                }
            }
        )*
    };
}

impl_sub_primitive!(u8, u16, u32, u64, u128);

impl CheckedSub for BigUint {
    fn checked_sub(&self, rhs: &Self) -> Option<Self> {
        if arithmetic::cmp(&self.limbs, &rhs.limbs) == Ordering::Less {
            return None;
        }
        let mut limbs = self.limbs.clone();
        let success = sub_assign_limbs(&mut limbs, &rhs.limbs);
        debug_assert!(success);
        Some(Self::from_limbs(limbs))
    }
}

impl SaturatingSub for BigUint {
    fn saturating_sub(&self, rhs: &Self) -> Self {
        self.checked_sub(rhs).unwrap_or_default()
    }
}

fn sub_assign_limbs(lhs: &mut Vec<Limb>, rhs: &[Limb]) -> bool {
    if arithmetic::cmp(lhs, rhs) == Ordering::Less {
        return false;
    }

    let mut borrow = Limb::new(0);
    for index in 0..lhs.len() {
        let right = rhs.get(index).copied().unwrap_or_default();
        (lhs[index], borrow) = lhs[index].borrowing_sub(right, borrow);
    }
    debug_assert_eq!(borrow, Limb::new(0));
    arithmetic::normalize(lhs);
    true
}

fn sub_into_rhs(lhs: &[Limb], rhs: &mut Vec<Limb>) -> bool {
    if arithmetic::cmp(lhs, rhs) == Ordering::Less {
        return false;
    }

    let rhs_len = rhs.len();
    rhs.resize(lhs.len(), Limb::new(0));
    let mut borrow = Limb::new(0);
    for index in 0..lhs.len() {
        let right = if index < rhs_len { rhs[index] } else { Limb::new(0) };
        (rhs[index], borrow) = lhs[index].borrowing_sub(right, borrow);
    }
    debug_assert_eq!(borrow, Limb::new(0));
    arithmetic::normalize(rhs);
    true
}

fn sub_assign_u128(lhs: &mut Vec<Limb>, rhs: u128) -> bool {
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
    sub_assign_limbs(lhs, &words[..used])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_subtraction_reuses_each_available_operand_buffer() {
        let mut lhs = BigUint::from(u128::MAX);
        lhs.limbs.reserve(16);
        let lhs_pointer = lhs.limbs.as_ptr();
        let result = lhs - BigUint::from(1_u8);
        assert_eq!(result.limbs.as_ptr(), lhs_pointer);

        let lhs = BigUint::from(u128::MAX);
        let mut rhs = BigUint::from(1_u8);
        rhs.limbs.reserve(16);
        let rhs_pointer = rhs.limbs.as_ptr();
        let result = &lhs - rhs;
        assert_eq!(result.limbs.as_ptr(), rhs_pointer);
        assert_eq!(result, BigUint::from(u128::MAX - 1));
    }

    #[test]
    fn bigint_subtraction_supports_all_ownership_and_assignment_forms() {
        let left = BigUint::from(20_u8);
        let right = BigUint::from(6_u8);
        let expected = BigUint::from(14_u8);
        assert_eq!(&left - &right, expected);
        assert_eq!(&left - right.clone(), expected);
        assert_eq!(left.clone() - &right, expected);
        assert_eq!(left.clone() - right.clone(), expected);

        let mut value = left;
        value -= &right;
        assert_eq!(value, expected);
        value = BigUint::from(20_u8);
        value -= right;
        assert_eq!(value, expected);
    }

    #[test]
    fn primitive_subtraction_and_assignment_support_every_width() {
        assert_eq!(BigUint::from(10_u8) - 1_u8, BigUint::from(9_u8));
        assert_eq!(&BigUint::from(10_u8) - 2_u16, BigUint::from(8_u8));
        assert_eq!(BigUint::from(10_u8) - 3_u32, BigUint::from(7_u8));
        assert_eq!(&BigUint::from(10_u8) - 4_u64, BigUint::from(6_u8));
        assert_eq!(BigUint::from(u128::MAX) - u128::MAX, BigUint::default());

        let mut value = BigUint::from(u128::MAX);
        value -= 1_u8;
        value -= 2_u16;
        value -= 3_u32;
        value -= 4_u64;
        value -= 5_u128;
        assert_eq!(value, BigUint::from(u128::MAX - 15));
    }

    #[test]
    fn checked_sub_reports_underflow() {
        assert_eq!(BigUint::from(1_u8).checked_sub(&BigUint::from(2_u8)), None);
    }

    #[test]
    #[should_panic(expected = "attempted to subtract with underflow")]
    fn primitive_subtraction_panics_on_underflow() {
        let _ = BigUint::default() - 1_u8;
    }
}
