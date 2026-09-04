//! Fixed-width unsigned addition.

use core::ops::Add;

use crate::{FixedBigUint, Limb};

impl<const N: usize> Add<&FixedBigUint<N>> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    #[inline]
    fn add(self, rhs: &FixedBigUint<N>) -> Self::Output {
        let mut limbs = [Limb(0); N];
        let mut carry = Limb(0);
        let mut i = 0;

        while i < N {
            (limbs[i], carry) = self.limbs[i].carrying_add(rhs.limbs[i], carry);
            i += 1;
        }

        assert!(carry.0 == 0, "attempted to add with overflow");
        FixedBigUint { limbs }
    }
}

impl<const N: usize> Add<&FixedBigUint<N>> for FixedBigUint<N> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        &self + rhs
    }
}

impl<const N: usize> Add<FixedBigUint<N>> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    #[inline]
    fn add(self, rhs: FixedBigUint<N>) -> Self::Output {
        self + &rhs
    }
}

impl<const N: usize> Add for FixedBigUint<N> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

#[cfg(test)]
mod tests {
    use crate::{FixedBigUint, Limb, Word};

    #[test]
    fn adds_little_endian_limbs_with_carry() {
        let lhs = FixedBigUint {
            limbs: [Limb(Word::MAX), Limb(2)],
        };
        let rhs = FixedBigUint {
            limbs: [Limb(1), Limb(3)],
        };

        assert_eq!(
            &lhs + &rhs,
            FixedBigUint {
                limbs: [Limb(0), Limb(6)]
            }
        );
    }

    #[test]
    fn supports_all_owned_and_borrowed_combinations() {
        let lhs = || FixedBigUint::<1> { limbs: [Limb(1)] };
        let rhs = || FixedBigUint::<1> { limbs: [Limb(2)] };
        let expected = FixedBigUint::<1> { limbs: [Limb(3)] };

        assert_eq!(&lhs() + &rhs(), expected);
        assert_eq!(lhs() + &rhs(), expected);
        assert_eq!(&lhs() + rhs(), expected);
        assert_eq!(lhs() + rhs(), expected);
    }

    #[test]
    #[should_panic(expected = "attempted to add with overflow")]
    fn panics_when_the_fixed_width_overflows() {
        let lhs = FixedBigUint::<1> {
            limbs: [Limb(Word::MAX)],
        };
        let rhs = FixedBigUint::<1> { limbs: [Limb(1)] };

        let _ = lhs + rhs;
    }
}
