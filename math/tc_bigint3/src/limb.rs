//! Platform-sized words and limb arithmetic.

use core::ops::{Add, AddAssign, Sub, SubAssign};

#[cfg(target_pointer_width = "64")]
/// Platform-sized storage word.
pub type Word = u64;
#[cfg(not(target_pointer_width = "64"))]
/// Platform-sized storage word.
pub type Word = u32;

#[cfg(target_pointer_width = "64")]
/// Double-width intermediate word.
pub type WideWord = u128;
#[cfg(not(target_pointer_width = "64"))]
/// Double-width intermediate word.
pub type WideWord = u64;

/// One word of a multi-word integer.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Limb(pub Word);

impl Limb {
    /// Computes `self + rhs + carry` and returns the low word and carry word.
    #[inline(always)]
    pub const fn carrying_add(self, rhs: Self, carry: Self) -> (Self, Self) {
        let wide = self.0 as WideWord + rhs.0 as WideWord + carry.0 as WideWord;
        (Self(wide as Word), Self((wide >> Word::BITS) as Word))
    }

    /// Computes `self - rhs - borrow` and returns the low word and borrow word.
    #[inline(always)]
    pub const fn borrowing_sub(self, rhs: Self, borrow: Self) -> (Self, Self) {
        let (first, first_borrow) = self.0.overflowing_sub(rhs.0);
        let (result, second_borrow) = first.overflowing_sub(borrow.0);
        (Self(result), Self((first_borrow || second_borrow) as Word))
    }

    /// Computes `self + rhs` and reports overflow.
    #[inline(always)]
    pub const fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let (result, carry) = self.carrying_add(rhs, Self(0));
        (result, carry.0 != 0)
    }

    /// Computes `self - rhs` and reports underflow.
    #[inline(always)]
    pub const fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
        let (result, borrow) = self.borrowing_sub(rhs, Self(0));
        (result, borrow.0 != 0)
    }

    /// Returns the wrapping sum.
    #[inline(always)]
    pub const fn wrapping_add(self, rhs: Self) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }

    /// Returns the wrapping difference.
    #[inline(always)]
    pub const fn wrapping_sub(self, rhs: Self) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }
}

impl Add for Limb {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let (result, overflow) = self.overflowing_add(rhs);
        assert!(!overflow, "attempted to add with overflow");
        result
    }
}

impl AddAssign for Limb {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for Limb {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let (result, overflow) = self.overflowing_sub(rhs);
        assert!(!overflow, "attempted to subtract with underflow");
        result
    }
}

impl SubAssign for Limb {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::{Limb, Word};

    #[test]
    fn carrying_and_borrowing_report_the_extra_word() {
        assert_eq!(
            Limb(Word::MAX).carrying_add(Limb(0), Limb(1)),
            (Limb(0), Limb(1))
        );
        assert_eq!(
            Limb(0).borrowing_sub(Limb(Word::MAX), Limb(1)),
            (Limb(0), Limb(1))
        );
    }

    #[test]
    fn overflowing_and_wrapping_operations_match_word_arithmetic() {
        assert_eq!(Limb(Word::MAX).overflowing_add(Limb(1)), (Limb(0), true));
        assert_eq!(Limb(0).overflowing_sub(Limb(1)), (Limb(Word::MAX), true));
        assert_eq!(Limb(Word::MAX).wrapping_add(Limb(1)), Limb(0));
        assert_eq!(Limb(0).wrapping_sub(Limb(1)), Limb(Word::MAX));
    }

    #[test]
    fn add_sub_and_assign_operators_work_without_overflow() {
        assert_eq!(Limb(2) + Limb(3), Limb(5));
        assert_eq!(Limb(5) - Limb(3), Limb(2));

        let mut value = Limb(5);
        value += Limb(4);
        value -= Limb(3);
        assert_eq!(value, Limb(6));
    }

    #[test]
    #[should_panic(expected = "attempted to add with overflow")]
    fn add_panics_on_overflow() {
        let _ = Limb(Word::MAX) + Limb(1);
    }

    #[test]
    #[should_panic(expected = "attempted to subtract with underflow")]
    fn sub_panics_on_underflow() {
        let _ = Limb(0) - Limb(1);
    }
}
