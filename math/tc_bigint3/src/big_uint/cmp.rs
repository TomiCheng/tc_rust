//! Ordering for [`BigUint`].

use core::cmp::Ordering;

use crate::{BigUint, arithmetic};

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        arithmetic::cmp(&self.limbs, &other.limbs)
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_compares_significant_little_endian_limbs() {
        assert!(BigUint::from(u128::MAX) > BigUint::from(u64::MAX));
        assert_eq!(
            BigUint::from(7_u8).partial_cmp(&BigUint::from(7_u8)),
            Some(Ordering::Equal)
        );
    }
}
