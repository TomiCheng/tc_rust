//! Borrowed limb-slice views for [`BigUint`].

use crate::{BigUint, Limb};

impl AsRef<[Limb]> for BigUint {
    #[inline(always)]
    fn as_ref(&self) -> &[Limb] {
        self.as_limbs()
    }
}

#[cfg(test)]
mod tests {
    use crate::{BigUint, Limb};

    #[test]
    fn borrows_only_canonical_limbs() {
        let value = BigUint::from_u64(42);

        assert_eq!(AsRef::<[Limb]>::as_ref(&value), [Limb(42)]);
    }
}
