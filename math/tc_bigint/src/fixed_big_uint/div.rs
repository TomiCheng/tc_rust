//! Division and remainder for [`FixedBigUint`].

use core::ops::{Div, DivAssign, Rem, RemAssign};

use crate::traits::{CheckedDiv, CheckedRem, DivRem, RemEuclid};
use crate::{FixedBigUint, Limb, Word, arithmetic};

impl<const N: usize> FixedBigUint<N> {
    /// Returns the quotient and remainder together.
    pub fn div_rem(&self, rhs: &Self) -> (Self, Self) {
        let (quotient, remainder) = arithmetic::fixed_div_rem(&self.limbs, &rhs.limbs);
        (Self { limbs: quotient }, Self { limbs: remainder })
    }

    /// Returns the Euclidean remainder.
    pub fn rem_euclid(&self, divisor: &Self) -> Self {
        *self % *divisor
    }
}

impl<const N: usize> Div for FixedBigUint<N> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.div_rem(&rhs).0
    }
}

impl<const N: usize> Rem for FixedBigUint<N> {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        self.div_rem(&rhs).1
    }
}

macro_rules! impl_borrowed_division {
    ($trait:ident, $method:ident, $operator:tt) => {
        impl<const N: usize> $trait<&FixedBigUint<N>> for FixedBigUint<N> {
            type Output = FixedBigUint<N>;

            fn $method(self, rhs: &FixedBigUint<N>) -> Self::Output {
                self $operator *rhs
            }
        }

        impl<const N: usize> $trait<FixedBigUint<N>> for &FixedBigUint<N> {
            type Output = FixedBigUint<N>;

            fn $method(self, rhs: FixedBigUint<N>) -> Self::Output {
                *self $operator rhs
            }
        }

        impl<const N: usize> $trait<&FixedBigUint<N>> for &FixedBigUint<N> {
            type Output = FixedBigUint<N>;

            fn $method(self, rhs: &FixedBigUint<N>) -> Self::Output {
                *self $operator *rhs
            }
        }
    };
}

impl_borrowed_division!(Div, div, /);
impl_borrowed_division!(Rem, rem, %);

impl<const N: usize> DivAssign for FixedBigUint<N> {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<const N: usize> DivAssign<&FixedBigUint<N>> for FixedBigUint<N> {
    fn div_assign(&mut self, rhs: &FixedBigUint<N>) {
        *self = *self / *rhs;
    }
}

impl<const N: usize> RemAssign for FixedBigUint<N> {
    fn rem_assign(&mut self, rhs: Self) {
        *self = *self % rhs;
    }
}

impl<const N: usize> RemAssign<&FixedBigUint<N>> for FixedBigUint<N> {
    fn rem_assign(&mut self, rhs: &FixedBigUint<N>) {
        *self = *self % *rhs;
    }
}

macro_rules! impl_division_primitive {
    ($($primitive:ty),* $(,)?) => {
        $(
            impl<const N: usize> Div<$primitive> for FixedBigUint<N> {
                type Output = Self;

                fn div(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(&self, rhs as u128).0
                }
            }

            impl<const N: usize> Div<$primitive> for &FixedBigUint<N> {
                type Output = FixedBigUint<N>;

                fn div(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(self, rhs as u128).0
                }
            }

            impl<const N: usize> Rem<$primitive> for FixedBigUint<N> {
                type Output = Self;

                fn rem(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(&self, rhs as u128).1
                }
            }

            impl<const N: usize> Rem<$primitive> for &FixedBigUint<N> {
                type Output = FixedBigUint<N>;

                fn rem(self, rhs: $primitive) -> Self::Output {
                    div_rem_u128(self, rhs as u128).1
                }
            }

            impl<const N: usize> DivAssign<$primitive> for FixedBigUint<N> {
                fn div_assign(&mut self, rhs: $primitive) {
                    *self = div_rem_u128(self, rhs as u128).0;
                }
            }

            impl<const N: usize> RemAssign<$primitive> for FixedBigUint<N> {
                fn rem_assign(&mut self, rhs: $primitive) {
                    *self = div_rem_u128(self, rhs as u128).1;
                }
            }
        )*
    };
}

impl_division_primitive!(u8, u16, u32, u64, u128);

impl<const N: usize> DivRem for FixedBigUint<N> {
    type Quotient = Self;
    type Remainder = Self;

    fn div_rem(&self, rhs: &Self) -> (Self::Quotient, Self::Remainder) {
        FixedBigUint::div_rem(self, rhs)
    }
}

impl<const N: usize> RemEuclid for FixedBigUint<N> {
    type Output = Self;

    fn rem_euclid(&self, rhs: &Self) -> Self::Output {
        FixedBigUint::rem_euclid(self, rhs)
    }
}

impl<const N: usize> CheckedDiv for FixedBigUint<N> {
    fn checked_div(&self, rhs: &Self) -> Option<Self> {
        (!rhs.is_zero()).then(|| self.div_rem(rhs).0)
    }
}

impl<const N: usize> CheckedRem for FixedBigUint<N> {
    fn checked_rem(&self, rhs: &Self) -> Option<Self> {
        (!rhs.is_zero()).then(|| self.div_rem(rhs).1)
    }
}

fn div_rem_u128<const N: usize>(
    value: &FixedBigUint<N>,
    mut divisor: u128,
) -> (FixedBigUint<N>, FixedBigUint<N>) {
    assert!(divisor != 0, "attempted to divide by zero");
    let mut divisor_limbs = [Limb::new(0); N];
    for limb in &mut divisor_limbs {
        *limb = Limb::new(divisor as Word);
        divisor >>= Word::BITS;
    }
    if divisor != 0 {
        return (FixedBigUint::zero(), *value);
    }
    let (quotient, remainder) = arithmetic::fixed_div_rem(&value.limbs, &divisor_limbs);
    (
        FixedBigUint { limbs: quotient },
        FixedBigUint { limbs: remainder },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ToPrimitive;

    #[test]
    fn primitive_division_remainder_and_assignment_support_every_width() {
        let value = FixedBigUint::<4>::from(120_u8);
        assert_eq!(value / 2_u8, FixedBigUint::from(60_u8));
        assert_eq!(&value / 3_u16, FixedBigUint::from(40_u8));
        assert_eq!(value / 4_u32, FixedBigUint::from(30_u8));
        assert_eq!(&value / 5_u64, FixedBigUint::from(24_u8));
        assert_eq!(
            FixedBigUint::<4>::from(u128::MAX) / u128::MAX,
            FixedBigUint::from(1_u8)
        );

        assert_eq!(value % 7_u8, FixedBigUint::from(1_u8));
        assert_eq!(&value % 11_u16, FixedBigUint::from(10_u8));
        assert_eq!(value % 13_u32, FixedBigUint::from(3_u8));
        assert_eq!(&value % 17_u64, FixedBigUint::from(1_u8));
        assert_eq!(
            FixedBigUint::<4>::from(u128::MAX) % u128::MAX,
            FixedBigUint::zero()
        );

        let mut quotient = FixedBigUint::<4>::from(120_u8);
        quotient /= 3_u8;
        quotient /= 2_u16;
        quotient /= 2_u32;
        quotient /= 2_u64;
        quotient /= 5_u128;
        assert_eq!(quotient, FixedBigUint::from(1_u8));

        let mut remainder = FixedBigUint::<4>::from(120_u8);
        remainder %= 17_u8;
        remainder %= 7_u16;
        remainder %= 5_u32;
        remainder %= 3_u64;
        remainder %= 2_u128;
        assert_eq!(remainder, FixedBigUint::from(1_u8));
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn fixed_division_and_remainder_support_all_ownership_and_assignment_forms() {
        type U = FixedBigUint<4>;
        let left = U::from(20_u8);
        let right = U::from(6_u8);
        assert_eq!(left / right, U::from(3_u8));
        assert_eq!(left / &right, U::from(3_u8));
        assert_eq!(&left / right, U::from(3_u8));
        assert_eq!(&left / &right, U::from(3_u8));
        assert_eq!(left % right, U::from(2_u8));
        assert_eq!(left % &right, U::from(2_u8));
        assert_eq!(&left % right, U::from(2_u8));
        assert_eq!(&left % &right, U::from(2_u8));

        let mut quotient = left;
        quotient /= right;
        assert_eq!(quotient, U::from(3_u8));
        quotient = left;
        quotient /= &right;
        assert_eq!(quotient, U::from(3_u8));
        let mut remainder = left;
        remainder %= right;
        assert_eq!(remainder, U::from(2_u8));
        remainder = left;
        remainder %= &right;
        assert_eq!(remainder, U::from(2_u8));
    }

    #[test]
    fn fixed_division_matches_u128_and_div_rem_trait() {
        type U = FixedBigUint<{ 128 / Word::BITS as usize }>;
        let lhs = U::from(1_000_000_u64);
        let rhs = U::from(37_u8);
        assert_eq!((lhs / rhs).to_u128(), Some(1_000_000 / 37));
        assert_eq!((lhs % rhs).to_u128(), Some(1_000_000 % 37));
        assert_eq!(lhs.div_rem(&rhs), (lhs / rhs, lhs % rhs));
        assert_eq!(lhs.rem_euclid(&rhs), lhs % rhs);
    }

    #[test]
    fn checked_division_rejects_zero() {
        type U = FixedBigUint<2>;
        let value = U::from(17_u8);
        assert_eq!(value.checked_div(&U::from(5_u8)), Some(U::from(3_u8)));
        assert_eq!(value.checked_rem(&U::from(5_u8)), Some(U::from(2_u8)));
        assert_eq!(value.checked_div(&U::zero()), None);
        assert_eq!(value.checked_rem(&U::zero()), None);
    }

    #[test]
    fn divisor_wider_than_the_fixed_value_returns_zero_and_the_value() {
        let value = FixedBigUint::<1>::from(7_u8);
        assert_eq!(value / u128::MAX, FixedBigUint::zero());
        assert_eq!(value % u128::MAX, value);
    }

    #[test]
    #[should_panic(expected = "attempted to divide by zero")]
    fn primitive_division_rejects_zero() {
        let _ = FixedBigUint::<1>::from(1_u8) / 0_u8;
    }

    #[test]
    #[should_panic(expected = "attempted to divide by zero")]
    fn fixed_division_rejects_zero() {
        let _ = FixedBigUint::<2>::from(1_u8) / FixedBigUint::zero();
    }
}
