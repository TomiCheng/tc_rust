//! Subtraction for [`FixedBigUint`].

use core::ops::{Sub, SubAssign};

use crate::traits::{CheckedSub, OverflowingSub, SaturatingSub, WrappingSub};
use crate::{FixedBigUint, Limb, Word};

impl<const N: usize> Sub for FixedBigUint<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let (limbs, underflow) = self.limbs.sub(&rhs.limbs);
        assert!(!underflow, "attempted to subtract with underflow");
        Self { limbs }
    }
}

impl<const N: usize> Sub<&FixedBigUint<N>> for FixedBigUint<N> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self - *rhs
    }
}

impl<const N: usize> Sub<FixedBigUint<N>> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    fn sub(self, rhs: FixedBigUint<N>) -> Self::Output {
        *self - rhs
    }
}

impl<const N: usize> Sub<&FixedBigUint<N>> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    fn sub(self, rhs: &FixedBigUint<N>) -> Self::Output {
        *self - *rhs
    }
}

impl<const N: usize> SubAssign for FixedBigUint<N> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<const N: usize> SubAssign<&FixedBigUint<N>> for FixedBigUint<N> {
    fn sub_assign(&mut self, rhs: &FixedBigUint<N>) {
        *self = *self - *rhs;
    }
}

macro_rules! impl_sub_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl<const N: usize> Sub<$primitive> for FixedBigUint<N> {
                type Output = Self;

                fn sub(self, rhs: $primitive) -> Self::Output {
                    checked_sub_u128(&self, rhs as u128)
                        .expect("attempted to subtract with underflow")
                }
            }

            impl<const N: usize> Sub<$primitive> for &FixedBigUint<N> {
                type Output = FixedBigUint<N>;

                fn sub(self, rhs: $primitive) -> Self::Output {
                    *self - rhs
                }
            }

            impl<const N: usize> SubAssign<$primitive> for FixedBigUint<N> {
                fn sub_assign(&mut self, rhs: $primitive) {
                    *self = *self - rhs;
                }
            }
        )*
    };
}

impl_sub_primitive!(u8, u16, u32, u64, u128);

impl<const N: usize> CheckedSub for FixedBigUint<N> {
    fn checked_sub(&self, rhs: &Self) -> Option<Self> {
        let (limbs, underflow) = self.limbs.sub(&rhs.limbs);
        (!underflow).then_some(Self { limbs })
    }
}

impl<const N: usize> OverflowingSub for FixedBigUint<N> {
    fn overflowing_sub(&self, rhs: &Self) -> (Self, bool) {
        let (limbs, underflow) = self.limbs.sub(&rhs.limbs);
        (Self { limbs }, underflow)
    }
}

impl<const N: usize> WrappingSub for FixedBigUint<N> {
    fn wrapping_sub(&self, rhs: &Self) -> Self {
        self.overflowing_sub(rhs).0
    }
}

impl<const N: usize> SaturatingSub for FixedBigUint<N> {
    fn saturating_sub(&self, rhs: &Self) -> Self {
        self.checked_sub(rhs).unwrap_or_else(Self::zero)
    }
}

fn checked_sub_u128<const N: usize>(
    lhs: &FixedBigUint<N>,
    mut rhs: u128,
) -> Option<FixedBigUint<N>> {
    let mut limbs = lhs.limbs.into_limbs();
    let mut borrow = Limb::new(0);
    for limb in &mut limbs {
        let rhs_limb = Limb::new(rhs as Word);
        rhs >>= Word::BITS;
        (*limb, borrow) = limb.borrowing_sub(rhs_limb, borrow);
    }
    (rhs == 0 && borrow.to_word() == 0).then_some(FixedBigUint {
        limbs: crate::LimbArray::new(limbs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_subtraction_and_assignment_support_every_width() {
        assert_eq!(
            FixedBigUint::<4>::from(10_u8) - 1_u8,
            FixedBigUint::from(9_u8)
        );
        assert_eq!(
            &FixedBigUint::<4>::from(10_u8) - 2_u16,
            FixedBigUint::from(8_u8)
        );
        assert_eq!(
            FixedBigUint::<4>::from(10_u8) - 3_u32,
            FixedBigUint::from(7_u8)
        );
        assert_eq!(
            &FixedBigUint::<4>::from(10_u8) - 4_u64,
            FixedBigUint::from(6_u8)
        );
        assert_eq!(
            FixedBigUint::<4>::from(u128::MAX) - u128::MAX,
            FixedBigUint::zero()
        );

        let mut value = FixedBigUint::<4>::from(100_u8);
        value -= 1_u8;
        value -= 2_u16;
        value -= 3_u32;
        value -= 4_u64;
        value -= 5_u128;
        assert_eq!(value, FixedBigUint::from(85_u8));
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn fixed_subtraction_supports_all_ownership_and_assignment_forms() {
        type U = FixedBigUint<4>;
        let left = U::from(20_u8);
        let right = U::from(6_u8);
        let expected = U::from(14_u8);
        assert_eq!(left - right, expected);
        assert_eq!(left - &right, expected);
        assert_eq!(&left - right, expected);
        assert_eq!(&left - &right, expected);

        let mut value = left;
        value -= right;
        assert_eq!(value, expected);
        value = left;
        value -= &right;
        assert_eq!(value, expected);
    }

    #[test]
    #[should_panic(expected = "attempted to subtract with underflow")]
    fn fixed_subtraction_rejects_underflow() {
        let _ = FixedBigUint::<2>::zero() - FixedBigUint::from(1_u8);
    }

    #[test]
    fn checked_sub_reports_underflow() {
        assert_eq!(
            FixedBigUint::<2>::from(1_u8).checked_sub(&FixedBigUint::from(2_u8)),
            None
        );
    }

    #[test]
    fn subtraction_families_report_wrap_and_saturate() {
        type U = FixedBigUint<1>;
        let zero = U::zero();
        let one = U::from(1_u8);
        assert_eq!(zero.overflowing_sub(&one), (U::max_value(), true));
        assert_eq!(zero.wrapping_sub(&one), U::max_value());
        assert_eq!(zero.saturating_sub(&one), U::zero());
    }

    #[test]
    #[should_panic(expected = "attempted to subtract with underflow")]
    fn primitive_subtraction_rejects_underflow() {
        let _ = FixedBigUint::<1>::zero() - 1_u8;
    }
}
