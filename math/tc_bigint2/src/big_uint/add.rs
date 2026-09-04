//! Arbitrary-precision unsigned addition.

use alloc::vec::Vec;
use core::ops::Add;

use crate::{BigUint, Limb};

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

fn add_assign_limbs(lhs: &mut Vec<Limb>, rhs: &[Limb]) {
    if lhs.len() < rhs.len() {
        lhs.resize(rhs.len(), Limb(0));
    }

    let mut carry = Limb(0);
    let mut i = 0;

    while i < lhs.len() {
        let rhs_limb = rhs.get(i).copied().unwrap_or(Limb(0));
        (lhs[i], carry) = lhs[i].carrying_add(rhs_limb, carry);
        i += 1;
    }

    if carry.0 != 0 {
        lhs.push(carry);
    }
}

#[cfg(test)]
mod tests {
    use crate::{BigUint, Limb, Word};

    #[test]
    fn grows_when_the_high_limb_carries() {
        let lhs = BigUint {
            limbs: [Limb(Word::MAX)].into(),
        };
        let rhs = BigUint::from_u8(1);

        assert_eq!(
            lhs + rhs,
            BigUint {
                limbs: [Limb(0), Limb(1)].into()
            }
        );
    }

    #[test]
    fn adds_values_with_different_limb_lengths() {
        let lhs = BigUint {
            limbs: [Limb(1), Limb(2)].into(),
        };
        let rhs = BigUint::from_u8(3);

        assert_eq!(
            lhs + rhs,
            BigUint {
                limbs: [Limb(4), Limb(2)].into()
            }
        );
    }

    #[test]
    fn supports_all_owned_and_borrowed_combinations() {
        let lhs = || BigUint::from_u8(1);
        let rhs = || BigUint::from_u8(2);
        let expected = BigUint::from_u8(3);

        assert_eq!(&lhs() + &rhs(), expected);
        assert_eq!(lhs() + &rhs(), expected);
        assert_eq!(&lhs() + rhs(), expected);
        assert_eq!(lhs() + rhs(), expected);
    }
}
