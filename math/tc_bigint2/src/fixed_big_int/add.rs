//! Fixed-width signed addition.

use core::ops::Add;

use crate::{FixedBigInt, Limb, Word};

impl<const N: usize> Add<&FixedBigInt<N>> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    #[inline]
    fn add(self, rhs: &FixedBigInt<N>) -> Self::Output {
        let mut limbs = [Limb(0); N];
        let mut carry = Limb(0);
        let mut i = 0;

        while i < N {
            (limbs[i], carry) = self.limbs[i].carrying_add(rhs.limbs[i], carry);
            i += 1;
        }

        let lhs_negative = is_negative(&self.limbs);
        let rhs_negative = is_negative(&rhs.limbs);
        let result_negative = is_negative(&limbs);
        let overflow = lhs_negative == rhs_negative && result_negative != lhs_negative;

        assert!(!overflow, "attempted to add with overflow");
        FixedBigInt { limbs }
    }
}

impl<const N: usize> Add<&FixedBigInt<N>> for FixedBigInt<N> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        &self + rhs
    }
}

impl<const N: usize> Add<FixedBigInt<N>> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    #[inline]
    fn add(self, rhs: FixedBigInt<N>) -> Self::Output {
        self + &rhs
    }
}

impl<const N: usize> Add for FixedBigInt<N> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

#[inline(always)]
fn is_negative<const N: usize>(limbs: &[Limb; N]) -> bool {
    match limbs.last() {
        Some(limb) => limb.0 >> (Word::BITS - 1) != 0,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::{FixedBigInt, Limb, Word};

    #[test]
    fn adds_little_endian_limbs_with_carry() {
        let lhs = FixedBigInt {
            limbs: [Limb(Word::MAX), Limb(2)],
        };
        let rhs = FixedBigInt {
            limbs: [Limb(1), Limb(3)],
        };

        assert_eq!(
            &lhs + &rhs,
            FixedBigInt {
                limbs: [Limb(0), Limb(6)]
            }
        );
    }

    #[test]
    fn allows_an_unsigned_carry_when_the_signed_result_is_valid() {
        let negative_one = FixedBigInt::<1> {
            limbs: [Limb(Word::MAX)],
        };
        let one = FixedBigInt::<1> { limbs: [Limb(1)] };

        assert_eq!(negative_one + one, FixedBigInt::<1> { limbs: [Limb(0)] });
    }

    #[test]
    fn supports_all_owned_and_borrowed_combinations() {
        let lhs = || FixedBigInt::<1> { limbs: [Limb(1)] };
        let rhs = || FixedBigInt::<1> { limbs: [Limb(2)] };
        let expected = FixedBigInt::<1> { limbs: [Limb(3)] };

        assert_eq!(&lhs() + &rhs(), expected);
        assert_eq!(lhs() + &rhs(), expected);
        assert_eq!(&lhs() + rhs(), expected);
        assert_eq!(lhs() + rhs(), expected);
    }

    #[test]
    #[should_panic(expected = "attempted to add with overflow")]
    fn panics_on_positive_signed_overflow() {
        let max = FixedBigInt::<1> {
            limbs: [Limb(Word::MAX >> 1)],
        };
        let one = FixedBigInt::<1> { limbs: [Limb(1)] };

        let _ = max + one;
    }

    #[test]
    #[should_panic(expected = "attempted to add with overflow")]
    fn panics_on_negative_signed_overflow() {
        let min = FixedBigInt::<1> {
            limbs: [Limb(1 << (Word::BITS - 1))],
        };
        let negative_one = FixedBigInt::<1> {
            limbs: [Limb(Word::MAX)],
        };

        let _ = min + negative_one;
    }
}
