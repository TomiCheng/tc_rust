//! Greatest common divisor support for [`BigInt`].

use crate::BigInt;
use crate::traits::Gcd;

impl BigInt {
    /// Returns the non-negative greatest common divisor.
    pub fn gcd(&self, other: &Self) -> Self {
        let mut left = self.abs();
        let mut right = other.abs();
        while !right.is_zero() {
            let remainder = &left % &right;
            left = right;
            right = remainder;
        }
        left
    }
}

impl Gcd for BigInt {
    type Output = Self;

    fn gcd(&self, rhs: &Self) -> Self::Output {
        BigInt::gcd(self, rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcd_is_non_negative() {
        assert_eq!(
            BigInt::from(-12_i8).gcd(&BigInt::from(18_i8)),
            BigInt::from(6_i8)
        );
    }
}
