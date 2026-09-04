//! Ordering for [`BigInt`].

use core::cmp::Ordering;

use crate::{BigInt, arithmetic};

impl Ord for BigInt {
    fn cmp(&self, other: &Self) -> Ordering {
        let (lhs_negative, lhs_magnitude) = self.sign_magnitude();
        let (rhs_negative, rhs_magnitude) = other.sign_magnitude();
        match (lhs_negative, rhs_negative) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => arithmetic::cmp(&lhs_magnitude, &rhs_magnitude),
            (true, true) => arithmetic::cmp(&rhs_magnitude, &lhs_magnitude),
        }
    }
}

impl PartialOrd for BigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_handles_sign_and_reverses_negative_magnitudes() {
        assert!(BigInt::from(-10_i8) < BigInt::from(-2_i8));
        assert!(BigInt::from(-1_i8) < BigInt::default());
        assert!(BigInt::from(10_u8) > BigInt::from(2_u8));
        assert_eq!(
            BigInt::from(7_i8).partial_cmp(&BigInt::from(7_i8)),
            Some(Ordering::Equal)
        );
    }
}
