//! Borrowed limb-slice views for [`FixedBigInt`].

use crate::{FixedBigInt, Limb};

impl<const N: usize> AsRef<[Limb]> for FixedBigInt<N> {
    #[inline(always)]
    fn as_ref(&self) -> &[Limb] {
        self.as_limbs()
    }
}

#[cfg(test)]
mod tests {
    use crate::{I128, Limb, Word};

    #[test]
    fn borrows_all_fixed_limbs() {
        let value = I128::from_i64(-1);
        let limbs: &[Limb] = value.as_ref();

        assert_eq!(limbs.len() as u32 * Word::BITS, 128);
    }
}
