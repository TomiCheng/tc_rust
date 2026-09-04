//! Borrowed limb-slice views for [`FixedBigUint`].

use crate::{FixedBigUint, Limb};

impl<const N: usize> AsRef<[Limb]> for FixedBigUint<N> {
    #[inline(always)]
    fn as_ref(&self) -> &[Limb] {
        self.as_limbs()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Limb, U128, Word};

    #[test]
    fn borrows_all_fixed_limbs() {
        let value = U128::from_u64(42);
        let limbs: &[Limb] = value.as_ref();

        assert_eq!(limbs.len() as u32 * Word::BITS, 128);
    }
}
