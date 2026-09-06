//! Subtraction for [`FixedBigInt`].

use core::ops::{Sub, SubAssign};

use crate::traits::{CheckedSub, OverflowingSub, SaturatingSub, WrappingSub};
use crate::{FixedBigInt, Limb, Word, arithmetic};

impl<const N: usize> Sub for FixedBigInt<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let (limbs, _) = arithmetic::fixed_sub(&self.limbs, &rhs.limbs);
        let overflow = self.is_negative() != rhs.is_negative()
            && arithmetic::fixed_is_negative(&limbs) != self.is_negative();
        assert!(!overflow, "attempted to subtract with overflow");
        Self { limbs }
    }
}

impl<const N: usize> Sub<&FixedBigInt<N>> for FixedBigInt<N> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self - *rhs
    }
}

impl<const N: usize> Sub<FixedBigInt<N>> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    fn sub(self, rhs: FixedBigInt<N>) -> Self::Output {
        *self - rhs
    }
}

impl<const N: usize> Sub<&FixedBigInt<N>> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    fn sub(self, rhs: &FixedBigInt<N>) -> Self::Output {
        *self - *rhs
    }
}

impl<const N: usize> SubAssign for FixedBigInt<N> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<const N: usize> SubAssign<&FixedBigInt<N>> for FixedBigInt<N> {
    fn sub_assign(&mut self, rhs: &FixedBigInt<N>) {
        *self = *self - *rhs;
    }
}

macro_rules! impl_sub_unsigned_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl<const N: usize> Sub<$primitive> for FixedBigInt<N> {
                type Output = Self;

                fn sub(self, rhs: $primitive) -> Self::Output {
                    checked_sub_u128(&self, rhs as u128)
                        .expect("attempted to subtract with overflow")
                }
            }

            impl<const N: usize> Sub<$primitive> for &FixedBigInt<N> {
                type Output = FixedBigInt<N>;

                fn sub(self, rhs: $primitive) -> Self::Output {
                    *self - rhs
                }
            }

            impl<const N: usize> SubAssign<$primitive> for FixedBigInt<N> {
                fn sub_assign(&mut self, rhs: $primitive) {
                    *self = *self - rhs;
                }
            }
        )*
    };
}

impl_sub_unsigned_primitive!(u8, u16, u32, u64, u128);

impl<const N: usize> CheckedSub for FixedBigInt<N> {
    fn checked_sub(&self, rhs: &Self) -> Option<Self> {
        let (limbs, _) = arithmetic::fixed_sub(&self.limbs, &rhs.limbs);
        let overflow = self.is_negative() != rhs.is_negative()
            && arithmetic::fixed_is_negative(&limbs) != self.is_negative();
        (!overflow).then_some(Self { limbs })
    }
}

impl<const N: usize> OverflowingSub for FixedBigInt<N> {
    fn overflowing_sub(&self, rhs: &Self) -> (Self, bool) {
        let (limbs, _) = arithmetic::fixed_sub(&self.limbs, &rhs.limbs);
        let overflow = self.is_negative() != rhs.is_negative()
            && arithmetic::fixed_is_negative(&limbs) != self.is_negative();
        (Self { limbs }, overflow)
    }
}

impl<const N: usize> WrappingSub for FixedBigInt<N> {
    fn wrapping_sub(&self, rhs: &Self) -> Self {
        self.overflowing_sub(rhs).0
    }
}

impl<const N: usize> SaturatingSub for FixedBigInt<N> {
    fn saturating_sub(&self, rhs: &Self) -> Self {
        self.checked_sub(rhs).unwrap_or_else(|| {
            if self.is_negative() {
                Self::min_value()
            } else {
                Self::max_value()
            }
        })
    }
}

fn checked_sub_u128<const N: usize>(lhs: &FixedBigInt<N>, mut rhs: u128) -> Option<FixedBigInt<N>> {
    let width = N * Word::BITS as usize;
    if width == 0 {
        return (rhs == 0).then_some(*lhs);
    }

    if width <= 128 {
        let lhs_value = lhs
            .checked_i128()
            .expect("a fixed integer of at most 128 bits always fits i128");
        let min_magnitude = 1_u128 << (width - 1);
        let headroom = if lhs_value < 0 {
            min_magnitude - lhs_value.unsigned_abs()
        } else {
            min_magnitude + lhs_value as u128
        };
        if rhs > headroom {
            return None;
        }
    }

    let mut limbs = lhs.limbs;
    let mut borrow = Limb::new(0);
    for limb in &mut limbs {
        let rhs_limb = Limb::new(rhs as Word);
        rhs >>= Word::BITS;
        (*limb, borrow) = limb.borrowing_sub(rhs_limb, borrow);
    }

    if width > 128 && lhs.is_negative() && !arithmetic::fixed_is_negative(&limbs) {
        return None;
    }
    Some(FixedBigInt { limbs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_subtraction_and_assignment_support_every_width() {
        assert_eq!(
            FixedBigInt::<4>::from(10_i8) - 1_u8,
            FixedBigInt::from(9_i8)
        );
        assert_eq!(
            &FixedBigInt::<4>::from(10_i8) - 2_u16,
            FixedBigInt::from(8_i8)
        );
        assert_eq!(
            FixedBigInt::<4>::from(10_i8) - 3_u32,
            FixedBigInt::from(7_i8)
        );
        assert_eq!(
            &FixedBigInt::<4>::from(10_i8) - 4_u64,
            FixedBigInt::from(6_i8)
        );
        assert_eq!(
            FixedBigInt::<8>::from(-1_i8) - u128::MAX,
            FixedBigInt::<8>::from(i128::MIN) * FixedBigInt::from(2_u8)
        );

        let mut value = FixedBigInt::<4>::from(100_i16);
        value -= 1_u8;
        value -= 2_u16;
        value -= 3_u32;
        value -= 4_u64;
        value -= 5_u128;
        assert_eq!(value, FixedBigInt::from(85_i8));
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn fixed_subtraction_supports_all_ownership_and_assignment_forms() {
        type I = FixedBigInt<4>;
        let left = I::from(-20_i8);
        let right = I::from(6_i8);
        let expected = I::from(-26_i8);
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
    #[should_panic(expected = "attempted to subtract with overflow")]
    fn fixed_subtraction_rejects_overflow() {
        type I = FixedBigInt<2>;
        let _ = I::min_value() - I::from(1_u8);
    }

    #[test]
    fn checked_sub_reports_signed_overflow() {
        assert_eq!(
            FixedBigInt::<2>::min_value().checked_sub(&FixedBigInt::from(1_u8)),
            None
        );
    }

    #[test]
    fn subtraction_families_report_wrap_and_saturate() {
        type I = FixedBigInt<1>;
        let min = I::min_value();
        let one = I::from(1_i8);
        let (wrapped, overflow) = min.overflowing_sub(&one);
        assert!(overflow);
        assert_eq!(wrapped, I::max_value());
        assert_eq!(min.wrapping_sub(&one), I::max_value());
        assert_eq!(min.saturating_sub(&one), min);
    }

    #[test]
    #[should_panic(expected = "attempted to subtract with overflow")]
    fn primitive_subtraction_rejects_signed_overflow() {
        let _ = FixedBigInt::<{ 128 / Word::BITS as usize }>::from(i128::MIN) - 1_u8;
    }
}
