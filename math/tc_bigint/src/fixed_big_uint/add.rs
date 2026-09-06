//! Addition for [`FixedBigUint`].

use core::ops::{Add, AddAssign};

use crate::arithmetic;
use crate::traits::{CheckedAdd, OverflowingAdd, SaturatingAdd, WrappingAdd};
use crate::{FixedBigUint, Limb, Word};

impl<const N: usize> Add for FixedBigUint<N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(&rhs)
            .expect("attempted to add with overflow")
    }
}

impl<const N: usize> Add<&FixedBigUint<N>> for FixedBigUint<N> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self + *rhs
    }
}

impl<const N: usize> Add<FixedBigUint<N>> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    fn add(self, rhs: FixedBigUint<N>) -> Self::Output {
        *self + rhs
    }
}

impl<const N: usize> Add<&FixedBigUint<N>> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    fn add(self, rhs: &FixedBigUint<N>) -> Self::Output {
        *self + *rhs
    }
}

impl<const N: usize> AddAssign for FixedBigUint<N> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<const N: usize> AddAssign<&FixedBigUint<N>> for FixedBigUint<N> {
    fn add_assign(&mut self, rhs: &FixedBigUint<N>) {
        *self = *self + *rhs;
    }
}

macro_rules! impl_add_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl<const N: usize> Add<$primitive> for FixedBigUint<N> {
                type Output = Self;

                #[inline]
                fn add(self, rhs: $primitive) -> Self::Output {
                    let (limbs, overflow) = overflowing_add_u128(&self.limbs, rhs as u128);
                    assert!(!overflow, "attempted to add with overflow");
                    Self { limbs }
                }
            }

            impl<const N: usize> Add<$primitive> for &FixedBigUint<N> {
                type Output = FixedBigUint<N>;

                #[inline]
                fn add(self, rhs: $primitive) -> Self::Output {
                    *self + rhs
                }
            }

            impl<const N: usize> AddAssign<$primitive> for FixedBigUint<N> {
                #[inline]
                fn add_assign(&mut self, rhs: $primitive) {
                    *self = *self + rhs;
                }
            }
        )*
    };
}

impl_add_primitive!(u8, u16, u32, u64, u128);

impl<const N: usize> CheckedAdd for FixedBigUint<N> {
    fn checked_add(&self, rhs: &Self) -> Option<Self> {
        let (limbs, overflow) = arithmetic::fixed_add(&self.limbs, &rhs.limbs);
        (!overflow).then_some(Self { limbs })
    }
}

impl<const N: usize> OverflowingAdd for FixedBigUint<N> {
    fn overflowing_add(&self, rhs: &Self) -> (Self, bool) {
        let (limbs, overflow) = arithmetic::fixed_add(&self.limbs, &rhs.limbs);
        (Self { limbs }, overflow)
    }
}

impl<const N: usize> WrappingAdd for FixedBigUint<N> {
    fn wrapping_add(&self, rhs: &Self) -> Self {
        self.overflowing_add(rhs).0
    }
}

impl<const N: usize> SaturatingAdd for FixedBigUint<N> {
    fn saturating_add(&self, rhs: &Self) -> Self {
        self.checked_add(rhs).unwrap_or_else(Self::max_value)
    }
}

impl<const N: usize> FixedBigUint<N> {
    pub(super) fn checked_add_word(&self, value: Word) -> Option<Self> {
        let mut result = self.limbs;
        let mut carry = Limb::new(value);
        for word in &mut result {
            if carry.to_word() == 0 {
                break;
            }
            (*word, carry) = word.carrying_add(carry, Limb::new(0));
        }
        (carry.to_word() == 0).then_some(Self { limbs: result })
    }
}

#[inline]
fn overflowing_add_u128<const N: usize>(lhs: &[Limb; N], mut rhs: u128) -> ([Limb; N], bool) {
    let mut limbs = *lhs;
    let mut carry = Limb::new(0);

    for limb in &mut limbs {
        let rhs_limb = Limb::new(rhs as Word);
        rhs >>= Word::BITS;
        (*limb, carry) = limb.carrying_add(rhs_limb, carry);
    }

    (limbs, rhs != 0 || carry.to_word() != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_addition_supports_every_unsigned_width_directly() {
        assert_eq!(
            FixedBigUint::<4>::from(1_u8) + 2_u8,
            FixedBigUint::from(3_u8)
        );
        assert_eq!(
            &FixedBigUint::<4>::from(1_u8) + 2_u16,
            FixedBigUint::from(3_u8)
        );
        assert_eq!(
            FixedBigUint::<4>::from(1_u8) + 2_u32,
            FixedBigUint::from(3_u8)
        );
        assert_eq!(
            &FixedBigUint::<4>::from(1_u8) + 2_u64,
            FixedBigUint::from(3_u8)
        );
        assert_eq!(
            FixedBigUint::<4>::from(1_u8) + 2_u128,
            FixedBigUint::from(3_u8)
        );

        let mut value = FixedBigUint::<8>::from(1_u8);
        value += u8::MAX;
        value += u16::MAX;
        value += u32::MAX;
        value += u64::MAX;
        value += u128::MAX;
        assert_eq!(
            value,
            FixedBigUint::<8>::from(1_u8)
                + FixedBigUint::from(u8::MAX)
                + FixedBigUint::from(u16::MAX)
                + FixedBigUint::from(u32::MAX)
                + FixedBigUint::from(u64::MAX)
                + FixedBigUint::from(u128::MAX)
        );
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn fixed_addition_supports_all_ownership_and_assignment_forms() {
        type U = FixedBigUint<4>;
        let left = U::from(20_u8);
        let right = U::from(6_u8);
        let expected = U::from(26_u8);
        assert_eq!(left + right, expected);
        assert_eq!(left + &right, expected);
        assert_eq!(&left + right, expected);
        assert_eq!(&left + &right, expected);

        let mut value = left;
        value += right;
        assert_eq!(value, expected);
        value = left;
        value += &right;
        assert_eq!(value, expected);
    }

    #[test]
    fn checked_wrapping_overflowing_and_saturating_add_are_distinct() {
        type U = FixedBigUint<2>;
        let max = U::max_value();
        let one = U::from(1_u8);
        assert_eq!(max.checked_add(&one), None);
        assert_eq!(max.overflowing_add(&one), (U::zero(), true));
        assert_eq!(max.wrapping_add(&one), U::zero());
        assert_eq!(max.saturating_add(&one), max);
    }

    #[test]
    #[should_panic(expected = "attempted to add with overflow")]
    fn fixed_addition_rejects_overflow() {
        type U = FixedBigUint<2>;
        let _ = U::max_value() + U::from(1_u8);
    }

    #[test]
    #[should_panic(expected = "attempted to add with overflow")]
    fn primitive_addition_rejects_a_value_wider_than_the_destination() {
        let _ = FixedBigUint::<1>::zero() + u128::MAX;
    }
}
