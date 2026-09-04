//! Ordering for [`FixedBigUint`].

use core::cmp::Ordering;

use crate::{FixedBigUint, arithmetic};

impl<const N: usize> Ord for FixedBigUint<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        arithmetic::fixed_cmp(&self.limbs, &other.limbs)
    }
}

impl<const N: usize> PartialOrd for FixedBigUint<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_compares_high_limbs_first() {
        type U = FixedBigUint<4>;
        assert!(U::from(u128::MAX) > U::from(u64::MAX));
        assert_eq!(
            U::from(7_u8).partial_cmp(&U::from(7_u8)),
            Some(Ordering::Equal)
        );
    }
}
