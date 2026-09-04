//! A platform-sized word with big-integer arithmetic semantics.

use core::slice;

use crate::Word;

mod add;

/// A single word of a multi-word integer.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Limb(pub Word);

impl Limb {
    /// Reinterprets a limb slice as its underlying platform words.
    #[inline(always)]
    #[must_use]
    pub fn slice_as_words(limbs: &[Self]) -> &[Word] {
        // SAFETY: `Limb` is transparent over `Word`, so both types have the
        // same layout and alignment. The returned slice preserves the input
        // pointer, length, and lifetime.
        unsafe { slice::from_raw_parts(limbs.as_ptr().cast::<Word>(), limbs.len()) }
    }
}

impl AsRef<[Limb]> for Limb {
    #[inline(always)]
    fn as_ref(&self) -> &[Limb] {
        slice::from_ref(self)
    }
}

impl AsMut<[Limb]> for Limb {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [Limb] {
        slice::from_mut(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Limb, Word};

    #[test]
    fn slice_as_words_borrows_the_same_storage() {
        let limbs = [Limb(1), Limb(2), Limb(3)];
        let words = Limb::slice_as_words(&limbs);

        assert_eq!(words, [1, 2, 3]);
        assert_eq!(words.len(), limbs.len());
        assert!(core::ptr::eq(words.as_ptr(), limbs.as_ptr().cast::<Word>()));
    }

    #[test]
    fn as_ref_returns_a_slice_over_the_same_limb() {
        let limb = Limb(42);
        let limbs: &[Limb] = limb.as_ref();

        assert_eq!(limbs, [Limb(42)]);
        assert!(core::ptr::eq(limbs.as_ptr(), &limb));
    }

    #[test]
    fn as_mut_returns_a_slice_over_the_same_limb() {
        let mut limb = Limb(42);

        {
            let limbs: &mut [Limb] = limb.as_mut();
            assert_eq!(limbs.len(), 1);
            limbs[0] = Limb(24);
        }

        assert_eq!(limb, Limb(24));
    }
}
