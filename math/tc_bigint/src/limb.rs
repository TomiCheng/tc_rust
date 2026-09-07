pub(crate) mod array;
pub(crate) mod slice;

use crate::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(target_pointer_width = "64")]
/// Uses `u64` on 64-bit platforms and `u32` on 16-bit and 32-bit platforms, matching `tc_bigint`.
pub type Word = u64;
#[cfg(not(target_pointer_width = "64"))]
/// Uses `u64` on 64-bit platforms and `u32` on 16-bit and 32-bit platforms, matching `tc_bigint`.
pub type Word = u32;
#[cfg(target_pointer_width = "64")]
/// An intermediate arithmetic type with twice the bit width of [`Word`].
pub type WideWord = u128;
#[cfg(not(target_pointer_width = "64"))]
/// An intermediate arithmetic type with twice the bit width of [`Word`].
pub type WideWord = u64;

/// A single storage word, accessed through [`Self::new`] and [`Self::to_word`].
///
/// Arithmetic is exposed through named methods that make overflow behavior explicit.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Limb(Word);

impl Limb {
    /// Creates a limb from a native word.
    pub const fn new(word: Word) -> Self {
        Self(word)
    }

    /// Returns the native word without changing its value.
    pub const fn to_word(self) -> Word {
        self.0
    }

    /// Computes `self + rhs + carry`, returning the low word and carry word; `carry` may be any word.
    #[inline(always)]
    pub const fn carrying_add(self, rhs: Self, carry: Self) -> (Self, Self) {
        let wide = self.0 as WideWord + rhs.0 as WideWord + carry.0 as WideWord;
        (Self(wide as Word), Self((wide >> Word::BITS) as Word))
    }

    /// Computes `self - rhs - borrow`, returning the low word and borrow bit.
    ///
    /// # Panics
    /// Panics if `borrow` is neither zero nor one.
    #[inline(always)]
    pub const fn borrowing_sub(self, rhs: Self, borrow: Self) -> (Self, Self) {
        assert!(borrow.0 <= 1, "borrow must be zero or one");
        let (first, first_borrow) = self.0.overflowing_sub(rhs.0);
        let (result, second_borrow) = first.overflowing_sub(borrow.0);
        (Self(result), Self((first_borrow | second_borrow) as Word))
    }

    /// Returns the truncated sum and an overflow flag.
    pub const fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let (value, carry) = self.carrying_add(rhs, Self(0));
        (value, carry.0 != 0)
    }

    /// Returns the truncated difference and a borrow flag.
    pub const fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
        let (value, borrow) = self.borrowing_sub(rhs, Self(0));
        (value, borrow.0 != 0)
    }

    /// Adds modulo `2^Word::BITS`.
    pub const fn wrapping_add(self, rhs: Self) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }

    /// Subtracts modulo `2^Word::BITS`.
    pub const fn wrapping_sub(self, rhs: Self) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }

    /// Returns the low and high words of the full product.
    pub const fn widening_mul(self, rhs: Self) -> (Self, Self) {
        let wide = self.0 as WideWord * rhs.0 as WideWord;
        (Self(wide as Word), Self((wide >> Word::BITS) as Word))
    }

    /// Negates modulo `2^Word::BITS`, leaving zero unchanged.
    pub const fn wrapping_neg(self) -> Self {
        Self(self.0.wrapping_neg())
    }
}

/// Selects without branching on the choice bit or input values; zero selects `a`, and one selects `b`.
impl ConditionallySelectable for Limb {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Word::conditional_select(&a.0, &b.0, choice))
    }
}
/// Compares for equality without exiting early on a mismatch.
impl ConstantTimeEq for Limb {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.0.ct_eq(&rhs.0)
    }
}

#[cfg(test)]
mod doc_tests {
    use super::*;
    use crate::{Choice, ConditionallySelectable, ConstantTimeEq};

    #[test]
    fn limb_example() {
        let a = Limb::new(6);
        let b = Limb::new(3);
        assert_eq!(a.wrapping_add(b).to_word(), 9);
        assert_eq!(a.wrapping_sub(b).to_word(), 3);
        assert_eq!(a.widening_mul(b), (Limb::new(18), Limb::new(0)));
    }

    #[test]
    fn fn_example() {
        const VALUE: Limb = Limb::new(7);
        assert_eq!(VALUE.to_word(), 7);
    }

    #[test]
    fn fn_2_example() {
        assert_eq!(Limb::new(42).to_word(), 42);
    }

    #[test]
    fn fn_3_example() {
        let m = Limb::new(Word::MAX);
        assert_eq!(
            m.carrying_add(m, m),
            (Limb::new(Word::MAX - 2), Limb::new(2))
        );
    }

    #[test]
    fn fn_4_example() {
        assert_eq!(
            Limb::new(0).borrowing_sub(Limb::new(1), Limb::new(0)),
            (Limb::new(Word::MAX), Limb::new(1))
        );
    }

    #[test]
    fn fn_5_example() {
        assert_eq!(
            Limb::new(Word::MAX).overflowing_add(Limb::new(1)),
            (Limb::new(0), true)
        );
    }

    #[test]
    fn fn_6_example() {
        assert_eq!(
            Limb::new(0).overflowing_sub(Limb::new(1)),
            (Limb::new(Word::MAX), true)
        );
    }

    #[test]
    fn fn_7_example() {
        assert_eq!(
            Limb::new(Word::MAX).wrapping_add(Limb::new(1)),
            Limb::new(0)
        );
    }

    #[test]
    fn fn_8_example() {
        assert_eq!(
            Limb::new(0).wrapping_sub(Limb::new(1)),
            Limb::new(Word::MAX)
        );
    }

    #[test]
    fn fn_9_example() {
        assert_eq!(
            Limb::new(Word::MAX).widening_mul(Limb::new(2)),
            (Limb::new(Word::MAX - 1), Limb::new(1))
        );
    }

    #[test]
    fn fn_10_example() {
        assert_eq!(Limb::new(1).wrapping_neg(), Limb::new(Word::MAX));
    }

    #[test]
    fn item_example() {
        assert_eq!(
            Limb::conditional_select(&Limb::new(2), &Limb::new(9), Choice::from_lsb(1)),
            Limb::new(9)
        );
    }

    #[test]
    fn item_2_example() {
        assert_eq!(Limb::new(5).ct_eq(&Limb::new(5)).unwrap_u8(), 1);
    }
}
