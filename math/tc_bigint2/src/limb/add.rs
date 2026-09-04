//! Limb addition.

use core::ops::{Add, AddAssign};

use crate::{Limb, WideWord, Word};

impl Limb {
    /// Computes `self + rhs`, returning the result and the carry.
    #[inline(always)]
    #[must_use]
    pub const fn overflowing_add(self, rhs: Self) -> (Self, Self) {
        self.carrying_add(rhs, Self(0))
    }

    /// Computes `self + rhs + carry`, returning the result and the new carry.
    #[inline(always)]
    #[must_use]
    pub const fn carrying_add(self, rhs: Self, carry: Self) -> (Self, Self) {
        let wide = self.0 as WideWord + rhs.0 as WideWord + carry.0 as WideWord;

        (Self(wide as Word), Self((wide >> Word::BITS) as Word))
    }

    /// Performs saturating addition.
    #[inline(always)]
    #[must_use]
    pub const fn saturating_add(&self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Performs wrapping addition, discarding overflow.
    #[inline(always)]
    #[must_use]
    pub const fn wrapping_add(&self, rhs: Self) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Add for Limb {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let (result, carry) = self.overflowing_add(rhs);
        assert!(carry.0 == 0, "attempted to add with overflow");
        result
    }
}

impl Add<&Limb> for Limb {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        self + *rhs
    }
}

impl AddAssign for Limb {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl AddAssign<&Limb> for Limb {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        *self += *rhs;
    }
}

#[cfg(test)]
mod tests {
    use crate::{Limb, Word};

    #[test]
    fn overflowing_add_returns_the_carry() {
        assert_eq!(Limb(1).overflowing_add(Limb(2)), (Limb(3), Limb(0)));
        assert_eq!(Limb(Word::MAX).overflowing_add(Limb(1)), (Limb(0), Limb(1)));
    }

    #[test]
    fn adds_without_carry() {
        assert_eq!(Limb(1).carrying_add(Limb(2), Limb(0)), (Limb(3), Limb(0)));
    }

    #[test]
    fn adds_an_input_carry() {
        assert_eq!(Limb(1).carrying_add(Limb(2), Limb(1)), (Limb(4), Limb(0)));
    }

    #[test]
    fn returns_an_output_carry() {
        assert_eq!(
            Limb(Word::MAX).carrying_add(Limb(1), Limb(0)),
            (Limb(0), Limb(1))
        );
    }

    #[test]
    fn accepts_a_full_limb_carry() {
        assert_eq!(
            Limb(Word::MAX).carrying_add(Limb(Word::MAX), Limb(Word::MAX)),
            (Limb(Word::MAX - 2), Limb(2))
        );
    }

    #[test]
    fn saturating_add_clamps_at_the_maximum() {
        assert_eq!(Limb(1).saturating_add(Limb(2)), Limb(3));
        assert_eq!(Limb(Word::MAX).saturating_add(Limb(1)), Limb(Word::MAX));
    }

    #[test]
    fn wrapping_add_discards_the_carry() {
        assert_eq!(Limb(1).wrapping_add(Limb(2)), Limb(3));
        assert_eq!(Limb(Word::MAX).wrapping_add(Limb(1)), Limb(0));
    }

    #[test]
    fn add_supports_owned_and_borrowed_rhs() {
        let rhs = Limb(2);

        assert_eq!(Limb(1) + Limb(2), Limb(3));
        assert_eq!(core::ops::Add::add(Limb(1), &rhs), Limb(3));
    }

    #[test]
    #[should_panic(expected = "attempted to add with overflow")]
    fn add_panics_on_overflow() {
        let _ = Limb(Word::MAX) + Limb(1);
    }

    #[test]
    fn add_assign_supports_owned_and_borrowed_rhs() {
        let mut value = Limb(1);
        value += Limb(2);
        assert_eq!(value, Limb(3));

        let rhs = Limb(4);
        value += &rhs;
        assert_eq!(value, Limb(7));
    }

    #[test]
    #[should_panic(expected = "attempted to add with overflow")]
    fn add_assign_panics_on_overflow() {
        let mut value = Limb(Word::MAX);
        value += Limb(1);
    }
}
