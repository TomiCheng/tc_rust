//! Multiplication for [`FixedBigUint`].

use core::ops::{Mul, MulAssign};

use crate::traits::{CheckedMul, OverflowingMul, SaturatingMul, Square, WrappingMul};
use crate::{FixedBigUint, Limb, WideWord, Word, arithmetic};

impl<const N: usize> FixedBigUint<N> {
    /// Returns `self * self`.
    pub fn square(&self) -> Self {
        *self * *self
    }

    pub(super) fn checked_mul_word(&self, value: Word) -> Option<Self> {
        let mut result = [Limb(0); N];
        let mut carry = 0 as Word;
        for (output, input) in result.iter_mut().zip(self.limbs) {
            let wide = input.0 as WideWord * value as WideWord + carry as WideWord;
            *output = Limb(wide as Word);
            carry = (wide >> Word::BITS) as Word;
        }
        (carry == 0).then_some(Self { limbs: result })
    }

    /// Returns `self * rhs`, or `None` when the product does not fit.
    pub fn checked_mul(&self, rhs: &Self) -> Option<Self> {
        let (limbs, overflow) = arithmetic::fixed_mul(&self.limbs, &rhs.limbs);
        (!overflow).then_some(Self { limbs })
    }

    /// Returns the full double-width product as `(low, high)` halves.
    ///
    /// The mathematical result is `low + high * 2^(N * Word::BITS)`.
    /// Both halves retain exactly `N` little-endian limbs and this operation
    /// does not allocate.
    ///
    /// ```
    /// use tc_bigint3::{FixedBigUint, Word};
    ///
    /// type U = FixedBigUint<1>;
    /// let (low, high) = U::max_value().mul_wide(&U::from(2_u8));
    /// assert_eq!(low, U::max_value() - U::from(1_u8));
    /// assert_eq!(high, U::from(1_u8));
    /// assert_eq!(U::max_value().square_wide(), U::max_value().mul_wide(&U::max_value()));
    /// # let _ = Word::BITS;
    /// ```
    pub fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        let (low, high) = arithmetic::fixed_mul_wide(&self.limbs, &rhs.limbs);
        (Self { limbs: low }, Self { limbs: high })
    }

    /// Returns the full double-width square as `(low, high)` halves.
    pub fn square_wide(&self) -> (Self, Self) {
        self.mul_wide(self)
    }
}

impl<const N: usize> Mul for FixedBigUint<N> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.checked_mul(&rhs)
            .expect("attempted to multiply with overflow")
    }
}

impl<const N: usize> Mul<&FixedBigUint<N>> for FixedBigUint<N> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self * *rhs
    }
}

impl<const N: usize> Mul<FixedBigUint<N>> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    fn mul(self, rhs: FixedBigUint<N>) -> Self::Output {
        *self * rhs
    }
}

impl<const N: usize> Mul<&FixedBigUint<N>> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    fn mul(self, rhs: &FixedBigUint<N>) -> Self::Output {
        *self * *rhs
    }
}

impl<const N: usize> MulAssign for FixedBigUint<N> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<const N: usize> MulAssign<&FixedBigUint<N>> for FixedBigUint<N> {
    fn mul_assign(&mut self, rhs: &FixedBigUint<N>) {
        *self = *self * *rhs;
    }
}

macro_rules! impl_mul_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl<const N: usize> Mul<$primitive> for FixedBigUint<N> {
                type Output = Self;

                fn mul(self, rhs: $primitive) -> Self::Output {
                    checked_mul_u128(&self, rhs as u128)
                        .expect("attempted to multiply with overflow")
                }
            }

            impl<const N: usize> Mul<$primitive> for &FixedBigUint<N> {
                type Output = FixedBigUint<N>;

                fn mul(self, rhs: $primitive) -> Self::Output {
                    *self * rhs
                }
            }

            impl<const N: usize> MulAssign<$primitive> for FixedBigUint<N> {
                fn mul_assign(&mut self, rhs: $primitive) {
                    *self = *self * rhs;
                }
            }
        )*
    };
}

impl_mul_primitive!(u8, u16, u32, u64, u128);

impl<const N: usize> Square for FixedBigUint<N> {
    type Output = Self;

    fn square(&self) -> Self::Output {
        FixedBigUint::square(self)
    }
}

impl<const N: usize> CheckedMul for FixedBigUint<N> {
    fn checked_mul(&self, rhs: &Self) -> Option<Self> {
        FixedBigUint::checked_mul(self, rhs)
    }
}

impl<const N: usize> OverflowingMul for FixedBigUint<N> {
    fn overflowing_mul(&self, rhs: &Self) -> (Self, bool) {
        let (limbs, overflow) = arithmetic::fixed_mul(&self.limbs, &rhs.limbs);
        (Self { limbs }, overflow)
    }
}

impl<const N: usize> WrappingMul for FixedBigUint<N> {
    fn wrapping_mul(&self, rhs: &Self) -> Self {
        self.overflowing_mul(rhs).0
    }
}

impl<const N: usize> SaturatingMul for FixedBigUint<N> {
    fn saturating_mul(&self, rhs: &Self) -> Self {
        self.checked_mul(rhs).unwrap_or_else(Self::max_value)
    }
}

fn checked_mul_u128<const N: usize>(
    lhs: &FixedBigUint<N>,
    mut rhs: u128,
) -> Option<FixedBigUint<N>> {
    let mut rhs_limbs = [Limb(0); N];
    for limb in &mut rhs_limbs {
        *limb = Limb(rhs as Word);
        rhs >>= Word::BITS;
    }
    if rhs != 0 && !lhs.is_zero() {
        return None;
    }
    let (limbs, overflow) = arithmetic::fixed_mul(&lhs.limbs, &rhs_limbs);
    (!overflow).then_some(FixedBigUint { limbs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ToPrimitive;

    #[test]
    fn primitive_multiplication_and_assignment_support_every_width() {
        assert_eq!(
            FixedBigUint::<4>::from(3_u8) * 2_u8,
            FixedBigUint::from(6_u8)
        );
        assert_eq!(
            &FixedBigUint::<4>::from(3_u8) * 3_u16,
            FixedBigUint::from(9_u8)
        );
        assert_eq!(
            FixedBigUint::<4>::from(3_u8) * 4_u32,
            FixedBigUint::from(12_u8)
        );
        assert_eq!(
            &FixedBigUint::<4>::from(3_u8) * 5_u64,
            FixedBigUint::from(15_u8)
        );
        assert_eq!(
            FixedBigUint::<4>::from(1_u8) * u128::MAX,
            FixedBigUint::from(u128::MAX)
        );

        let mut value = FixedBigUint::<4>::from(2_u8);
        value *= 2_u8;
        value *= 3_u16;
        value *= 4_u32;
        value *= 5_u64;
        value *= 6_u128;
        assert_eq!(value, FixedBigUint::from(1_440_u16));
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn fixed_multiplication_supports_all_ownership_and_assignment_forms() {
        type U = FixedBigUint<4>;
        let left = U::from(20_u8);
        let right = U::from(6_u8);
        let expected = U::from(120_u8);
        assert_eq!(left * right, expected);
        assert_eq!(left * &right, expected);
        assert_eq!(&left * right, expected);
        assert_eq!(&left * &right, expected);

        let mut value = left;
        value *= right;
        assert_eq!(value, expected);
        value = left;
        value *= &right;
        assert_eq!(value, expected);
    }

    #[test]
    fn fixed_multiplication_matches_u128() {
        type U = FixedBigUint<{ 128 / Word::BITS as usize }>;
        assert_eq!(
            (U::from(1_000_000_u64) * U::from(37_u8)).to_u128(),
            Some(37_000_000)
        );
    }

    #[test]
    fn checked_wrapping_overflowing_saturating_and_wide_products_are_distinct() {
        type U = FixedBigUint<1>;
        let max = U::max_value();
        let two = U::from(2_u8);
        assert_eq!(max.checked_mul(&two), None);
        assert_eq!(max.overflowing_mul(&two), (max - U::from(1_u8), true));
        assert_eq!(max.wrapping_mul(&two), max - U::from(1_u8));
        assert_eq!(max.saturating_mul(&two), max);
        assert_eq!(max.mul_wide(&two), (max - U::from(1_u8), U::from(1_u8)));
        assert_eq!(max.square_wide(), max.mul_wide(&max));
    }

    #[test]
    #[should_panic(expected = "attempted to multiply with overflow")]
    fn primitive_multiplication_rejects_overflow() {
        let _ = FixedBigUint::<1>::max_value() * 2_u8;
    }
}
