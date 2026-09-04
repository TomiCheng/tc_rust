//! Arbitrary-precision signed addition.

use alloc::vec::Vec;
use core::ops::Add;

use crate::{BigInt, Limb, Word};

impl Add<&BigInt> for &BigInt {
    type Output = BigInt;

    #[inline]
    fn add(self, rhs: &BigInt) -> Self::Output {
        let mut limbs = self.limbs.clone();
        add_assign_limbs(&mut limbs, &rhs.limbs);
        BigInt::from_limbs(limbs)
    }
}

impl Add<&BigInt> for BigInt {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Self) -> Self::Output {
        add_assign_limbs(&mut self.limbs, &rhs.limbs);
        Self::from_limbs(self.limbs)
    }
}

impl Add<BigInt> for &BigInt {
    type Output = BigInt;

    #[inline]
    fn add(self, mut rhs: BigInt) -> Self::Output {
        add_assign_limbs(&mut rhs.limbs, &self.limbs);
        BigInt::from_limbs(rhs.limbs)
    }
}

impl Add for BigInt {
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
    let lhs_extension = sign_extension(lhs);
    let rhs_extension = sign_extension(rhs);
    let width = lhs.len().max(rhs.len()) + 1;

    lhs.resize(width, lhs_extension);

    let mut carry = Limb(0);
    let mut i = 0;

    while i < width {
        let rhs_limb = rhs.get(i).copied().unwrap_or(rhs_extension);
        (lhs[i], carry) = lhs[i].carrying_add(rhs_limb, carry);
        i += 1;
    }
}

fn sign_extension(limbs: &[Limb]) -> Limb {
    match limbs.last() {
        Some(limb) if limb.0 >> (Word::BITS - 1) != 0 => Limb(Word::MAX),
        _ => Limb(0),
    }
}

#[cfg(test)]
mod tests {
    use crate::{BigInt, Limb, Word};

    #[test]
    fn grows_positive_precision_instead_of_overflowing() {
        let max = BigInt {
            limbs: [Limb(Word::MAX >> 1)].into(),
        };

        assert_eq!(
            max + BigInt::from_i8(1),
            BigInt {
                limbs: [Limb(1 << (Word::BITS - 1)), Limb(0)].into()
            }
        );
    }

    #[test]
    fn grows_negative_precision_instead_of_overflowing() {
        let min = BigInt {
            limbs: [Limb(1 << (Word::BITS - 1))].into(),
        };

        assert_eq!(
            min + BigInt::from_i8(-1),
            BigInt {
                limbs: [Limb((1 << (Word::BITS - 1)) - 1), Limb(Word::MAX)].into()
            }
        );
    }

    #[test]
    fn opposite_values_add_to_canonical_zero() {
        let result = BigInt::from_i8(-1) + BigInt::from_i8(1);

        assert!(result.limbs.is_empty());
    }

    #[test]
    fn supports_all_owned_and_borrowed_combinations() {
        let lhs = || BigInt::from_i8(-1);
        let rhs = || BigInt::from_i8(3);
        let expected = BigInt::from_i8(2);

        assert_eq!(&lhs() + &rhs(), expected);
        assert_eq!(lhs() + &rhs(), expected);
        assert_eq!(&lhs() + rhs(), expected);
        assert_eq!(lhs() + rhs(), expected);
    }
}
