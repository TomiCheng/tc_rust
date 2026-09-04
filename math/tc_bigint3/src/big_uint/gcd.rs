//! Greatest common divisor support for [`BigUint`].

use crate::BigUint;
use crate::traits::Gcd;

impl BigUint {
    /// Returns the greatest common divisor.
    pub fn gcd(&self, other: &Self) -> Self {
        let mut left = self.clone();
        let mut right = other.clone();
        while !right.is_zero() {
            let remainder = &left % &right;
            left = right;
            right = remainder;
        }
        left
    }
}

impl Gcd for BigUint {
    type Output = Self;

    fn gcd(&self, rhs: &Self) -> Self::Output {
        BigUint::gcd(self, rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcd_matches_known_value() {
        assert_eq!(
            BigUint::from(48_u8).gcd(&BigUint::from(18_u8)),
            BigUint::from(6_u8)
        );
    }
}
