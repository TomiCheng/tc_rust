//! Borrowed limb-slice views for [`BigInt`].

use crate::{BigInt, Limb};

impl AsRef<[Limb]> for BigInt {
    #[inline(always)]
    fn as_ref(&self) -> &[Limb] {
        self.as_limbs()
    }
}

#[cfg(test)]
mod tests {
    use crate::{BigInt, Limb, Word};

    #[test]
    fn borrows_only_canonical_limbs() {
        let value = BigInt::from_i64(-1);

        assert_eq!(AsRef::<[Limb]>::as_ref(&value), [Limb(Word::MAX)]);
    }
}
