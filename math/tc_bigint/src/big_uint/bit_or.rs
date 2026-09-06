//! Bitwise OR operations for [`BigUint`].

use core::ops::{BitOr, BitOrAssign};

use crate::{BigUint, Limb};

impl BitOr<&BigUint> for &BigUint {
    type Output = BigUint;

    fn bitor(self, rhs: &BigUint) -> Self::Output {
        let width = self.limbs.len().max(rhs.limbs.len());
        BigUint::from_limbs(
            (0..width)
                .map(|index| {
                    Limb::new(
                        self.limbs.get(index).map_or(0, |word| word.to_word())
                            | rhs.limbs.get(index).map_or(0, |word| word.to_word()),
                    )
                })
                .collect(),
        )
    }
}

impl BitOr<BigUint> for &BigUint {
    type Output = BigUint;

    fn bitor(self, rhs: BigUint) -> Self::Output {
        self | &rhs
    }
}

impl BitOr<&BigUint> for BigUint {
    type Output = BigUint;

    fn bitor(self, rhs: &BigUint) -> Self::Output {
        &self | rhs
    }
}

impl BitOr<BigUint> for BigUint {
    type Output = BigUint;

    fn bitor(self, rhs: BigUint) -> Self::Output {
        &self | &rhs
    }
}

impl BitOrAssign<&BigUint> for BigUint {
    fn bitor_assign(&mut self, rhs: &BigUint) {
        *self = &*self | rhs;
    }
}

impl BitOrAssign for BigUint {
    fn bitor_assign(&mut self, rhs: Self) {
        *self |= &rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitor_supports_all_ownership_forms() {
        let left = BigUint::from(0b1100_u8);
        let right = BigUint::from(0b1010_u8);
        let expected = BigUint::from(0b1110_u8);
        assert_eq!(&left | &right, expected);
        assert_eq!(&left | right.clone(), expected);
        assert_eq!(left.clone() | &right, expected);
        assert_eq!(left | right, expected);
    }
}
