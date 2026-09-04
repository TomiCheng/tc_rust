//! Bitwise XOR operations for [`BigInt`].

use core::ops::{BitXor, BitXorAssign};

use crate::BigInt;

impl BitXor<&BigInt> for &BigInt {
    type Output = BigInt;

    fn bitxor(self, rhs: &BigInt) -> Self::Output {
        BigInt::bitwise(self, rhs, |left, right| left ^ right)
    }
}

impl BitXor<BigInt> for &BigInt {
    type Output = BigInt;

    fn bitxor(self, rhs: BigInt) -> Self::Output {
        self ^ &rhs
    }
}

impl BitXor<&BigInt> for BigInt {
    type Output = BigInt;

    fn bitxor(self, rhs: &BigInt) -> Self::Output {
        &self ^ rhs
    }
}

impl BitXor<BigInt> for BigInt {
    type Output = BigInt;

    fn bitxor(self, rhs: BigInt) -> Self::Output {
        &self ^ &rhs
    }
}

impl BitXorAssign<&BigInt> for BigInt {
    fn bitxor_assign(&mut self, rhs: &BigInt) {
        *self = &*self ^ rhs;
    }
}

impl BitXorAssign for BigInt {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self ^= &rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ToPrimitive;

    #[test]
    fn bitxor_supports_all_ownership_forms_and_infinite_sign_extension() {
        let left = BigInt::from(-1_i8);
        let right = BigInt::from(0x1234_u16);
        let expected = BigInt::from(!0x1234_i64);
        assert_eq!(&left ^ &right, expected);
        assert_eq!(&left ^ right.clone(), expected);
        assert_eq!(left.clone() ^ &right, expected);
        assert_eq!((left ^ right).to_i64(), Some(!0x1234_i64));
    }
}
