use crate::{Choice, ConditionallySelectable, ConstantTimeEq};
use core::ops::{Add, AddAssign, BitAnd, BitOr, BitXor, Mul, Not, Shl, Shr, Sub, SubAssign};

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
/// `+`, `-`, and `*` panic on overflow, including in release builds; shift counts must be less than the word width.
/// Bitwise operations act on the entire word. Use `wrapping_*` methods when a truncated result is required.
///
/// ```
/// use tc_limb::{Limb, Word};
/// let a = Limb::new(6);
/// let b = Limb::new(3);
/// assert_eq!((a + b).to_word(), 9);
/// assert_eq!((a - b).to_word(), 3);
/// assert_eq!((a * b).to_word(), 18);
/// assert_eq!((a & b).to_word(), 2);
/// assert_eq!((a | b).to_word(), 7);
/// assert_eq!((a ^ b).to_word(), 5);
/// assert_eq!((!Limb::new(0)).to_word(), Word::MAX);
/// assert_eq!(((a << 1_usize) >> 1_usize), a);
/// let mut c = a;
/// c += b;
/// c -= b;
/// assert_eq!(c, a);
/// ```
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Limb(Word);

impl Limb {
    /// Creates a limb from a native word.
    /// ```
    /// use tc_limb::Limb;
    /// const VALUE: Limb = Limb::new(7);
    /// assert_eq!(VALUE.to_word(), 7);
    /// ```
    pub const fn new(word: Word) -> Self {
        Self(word)
    }

    /// Returns the native word without changing its value.
    /// ```
    /// use tc_limb::Limb;
    /// assert_eq!(Limb::new(42).to_word(), 42);
    /// ```
    pub const fn to_word(self) -> Word {
        self.0
    }

    /// Computes `self + rhs + carry`, returning the low word and carry word; `carry` may be any word.
    /// ```
    /// use tc_limb::{Limb, Word};
    /// let m = Limb::new(Word::MAX);
    /// assert_eq!(m.carrying_add(m, m), (Limb::new(Word::MAX - 2), Limb::new(2)));
    /// ```
    #[inline(always)]
    pub const fn carrying_add(self, rhs: Self, carry: Self) -> (Self, Self) {
        let wide = self.0 as WideWord + rhs.0 as WideWord + carry.0 as WideWord;
        (Self(wide as Word), Self((wide >> Word::BITS) as Word))
    }

    /// Computes `self - rhs - borrow`, returning the low word and borrow bit.
    ///
    /// # Panics
    /// Panics if `borrow` is neither zero nor one.
    /// ```
    /// use tc_limb::{Limb, Word};
    /// assert_eq!(Limb::new(0).borrowing_sub(Limb::new(1), Limb::new(0)),
    ///            (Limb::new(Word::MAX), Limb::new(1)));
    /// ```
    #[inline(always)]
    pub const fn borrowing_sub(self, rhs: Self, borrow: Self) -> (Self, Self) {
        assert!(borrow.0 <= 1, "borrow must be zero or one");
        let (first, first_borrow) = self.0.overflowing_sub(rhs.0);
        let (result, second_borrow) = first.overflowing_sub(borrow.0);
        (Self(result), Self((first_borrow | second_borrow) as Word))
    }

    /// Returns the truncated sum and an overflow flag.
    /// ```
    /// use tc_limb::{Limb, Word};
    /// assert_eq!(Limb::new(Word::MAX).overflowing_add(Limb::new(1)), (Limb::new(0), true));
    /// ```
    pub const fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let (value, carry) = self.carrying_add(rhs, Self(0));
        (value, carry.0 != 0)
    }

    /// Returns the truncated difference and a borrow flag.
    /// ```
    /// use tc_limb::{Limb, Word};
    /// assert_eq!(Limb::new(0).overflowing_sub(Limb::new(1)), (Limb::new(Word::MAX), true));
    /// ```
    pub const fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
        let (value, borrow) = self.borrowing_sub(rhs, Self(0));
        (value, borrow.0 != 0)
    }

    /// Adds modulo `2^Word::BITS`.
    /// ```
    /// use tc_limb::{Limb, Word};
    /// assert_eq!(Limb::new(Word::MAX).wrapping_add(Limb::new(1)), Limb::new(0));
    /// ```
    pub const fn wrapping_add(self, rhs: Self) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }

    /// Subtracts modulo `2^Word::BITS`.
    /// ```
    /// use tc_limb::{Limb, Word};
    /// assert_eq!(Limb::new(0).wrapping_sub(Limb::new(1)), Limb::new(Word::MAX));
    /// ```
    pub const fn wrapping_sub(self, rhs: Self) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }

    /// Returns the low and high words of the full product.
    /// ```
    /// use tc_limb::{Limb, Word};
    /// assert_eq!(Limb::new(Word::MAX).widening_mul(Limb::new(2)),
    ///            (Limb::new(Word::MAX - 1), Limb::new(1)));
    /// ```
    pub const fn widening_mul(self, rhs: Self) -> (Self, Self) {
        let wide = self.0 as WideWord * rhs.0 as WideWord;
        (Self(wide as Word), Self((wide >> Word::BITS) as Word))
    }

    /// Negates modulo `2^Word::BITS`, leaving zero unchanged.
    /// ```
    /// use tc_limb::{Limb, Word};
    /// assert_eq!(Limb::new(1).wrapping_neg(), Limb::new(Word::MAX));
    /// ```
    pub const fn wrapping_neg(self) -> Self {
        Self(self.0.wrapping_neg())
    }
}

impl Add for Limb {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let (value, overflow) = self.overflowing_add(rhs);
        assert!(!overflow, "attempted to add with overflow");
        value
    }
}
impl Sub for Limb {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let (value, overflow) = self.overflowing_sub(rhs);
        assert!(!overflow, "attempted to subtract with underflow");
        value
    }
}
impl Mul for Limb {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let (low, high) = self.widening_mul(rhs);
        assert!(high.0 == 0, "attempted to multiply with overflow");
        low
    }
}
impl AddAssign for Limb {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl SubAssign for Limb {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl BitAnd for Limb {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}
impl BitOr for Limb {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl BitXor for Limb {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}
impl Not for Limb {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}
impl Shl<usize> for Limb {
    type Output = Self;
    fn shl(self, shift: usize) -> Self {
        assert!(shift < Word::BITS as usize, "shift is outside word width");
        Self(self.0 << shift)
    }
}
impl Shr<usize> for Limb {
    type Output = Self;
    fn shr(self, shift: usize) -> Self {
        assert!(shift < Word::BITS as usize, "shift is outside word width");
        Self(self.0 >> shift)
    }
}

/// Selects without branching on the choice bit or input values; zero selects `a`, and one selects `b`.
/// ```
/// use tc_limb::{Choice, ConditionallySelectable, Limb};
/// assert_eq!(Limb::conditional_select(&Limb::new(2), &Limb::new(9), Choice::from_lsb(1)), Limb::new(9));
/// ```
impl ConditionallySelectable for Limb {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Word::conditional_select(&a.0, &b.0, choice))
    }
}
/// Compares for equality without exiting early on a mismatch.
/// ```
/// use tc_limb::{ConstantTimeEq, Limb};
/// assert_eq!(Limb::new(5).ct_eq(&Limb::new(5)).unwrap_u8(), 1);
/// ```
impl ConstantTimeEq for Limb {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.0.ct_eq(&rhs.0)
    }
}
