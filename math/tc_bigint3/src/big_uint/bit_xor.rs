//! Bitwise XOR operations for [`BigUint`].

use core::ops::BitXor;

use crate::{BigUint, Limb};

impl BitXor<&BigUint> for &BigUint {
    type Output = BigUint;

    fn bitxor(self, rhs: &BigUint) -> Self::Output {
        let width = self.limbs.len().max(rhs.limbs.len());
        BigUint::from_limbs(
            (0..width)
                .map(|index| {
                    Limb(
                        self.limbs.get(index).map_or(0, |word| word.0)
                            ^ rhs.limbs.get(index).map_or(0, |word| word.0),
                    )
                })
                .collect(),
        )
    }
}

impl BitXor<BigUint> for &BigUint {
    type Output = BigUint;

    fn bitxor(self, rhs: BigUint) -> Self::Output {
        self ^ &rhs
    }
}

impl BitXor<&BigUint> for BigUint {
    type Output = BigUint;

    fn bitxor(self, rhs: &BigUint) -> Self::Output {
        &self ^ rhs
    }
}

impl BitXor<BigUint> for BigUint {
    type Output = BigUint;

    fn bitxor(self, rhs: BigUint) -> Self::Output {
        &self ^ &rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitxor_supports_all_ownership_forms() {
        let left = BigUint::from(0b1100_u8);
        let right = BigUint::from(0b1010_u8);
        let expected = BigUint::from(0b0110_u8);
        assert_eq!(&left ^ &right, expected);
        assert_eq!(&left ^ right.clone(), expected);
        assert_eq!(left.clone() ^ &right, expected);
        assert_eq!(left ^ right, expected);
    }
}
