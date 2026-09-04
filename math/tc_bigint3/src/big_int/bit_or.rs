//! Bitwise OR operations for [`BigInt`].

use core::ops::{BitOr, BitOrAssign};

use crate::BigInt;

impl BitOr<&BigInt> for &BigInt {
    type Output = BigInt;

    fn bitor(self, rhs: &BigInt) -> Self::Output {
        BigInt::bitwise(self, rhs, |left, right| left | right)
    }
}

impl BitOr<BigInt> for &BigInt {
    type Output = BigInt;

    fn bitor(self, rhs: BigInt) -> Self::Output {
        self | &rhs
    }
}

impl BitOr<&BigInt> for BigInt {
    type Output = BigInt;

    fn bitor(self, rhs: &BigInt) -> Self::Output {
        &self | rhs
    }
}

impl BitOr<BigInt> for BigInt {
    type Output = BigInt;

    fn bitor(self, rhs: BigInt) -> Self::Output {
        &self | &rhs
    }
}

impl BitOrAssign<&BigInt> for BigInt {
    fn bitor_assign(&mut self, rhs: &BigInt) {
        *self = &*self | rhs;
    }
}

impl BitOrAssign for BigInt {
    fn bitor_assign(&mut self, rhs: Self) {
        *self |= &rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitor_supports_all_ownership_forms_and_infinite_sign_extension() {
        let left = BigInt::from(-1_i8);
        let right = BigInt::from(0x1234_u16);
        assert_eq!(&left | &right, left);
        assert_eq!(&left | right.clone(), left);
        assert_eq!(left.clone() | &right, left);
        assert_eq!(left.clone() | right, left);
    }
}
