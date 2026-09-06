//! Ordering for [`FixedBigInt`].

use core::cmp::Ordering;

use crate::FixedBigInt;

impl<const N: usize> Ord for FixedBigInt<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.is_negative(), other.is_negative()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => self.limbs.cmp(&other.limbs),
        }
    }
}

impl<const N: usize> PartialOrd for FixedBigInt<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_handles_sign_and_twos_complement_limbs() {
        type I = FixedBigInt<4>;
        assert!(I::from(-10_i8) < I::from(-2_i8));
        assert!(I::from(-1_i8) < I::zero());
        assert!(I::from(10_i8) > I::from(2_i8));
        assert_eq!(
            I::from(7_i8).partial_cmp(&I::from(7_i8)),
            Some(Ordering::Equal)
        );
    }
}
