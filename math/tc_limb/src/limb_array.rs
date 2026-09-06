use crate::{Choice, ConditionallySelectable, ConstantTimeEq, Limb};
use core::cmp::Ordering;

mod arithmetic;

/// Exactly `N` little-endian limbs, stored in a private field without heap allocation.
///
/// `N = 0` represents a zero-width zero; addition, subtraction, and multiplication return zero without overflow.
/// All limbs are unsigned storage, and the highest bit is not a sign bit; signed interpretation belongs to higher layers.
/// Ordinary comparisons, division, GCD, and other arithmetic are not guaranteed to run in constant time.
///
/// ```
/// use tc_limb::{Limb, LimbArray};
/// let value = LimbArray::new([Limb::new(7), Limb::new(0)]);
/// assert_eq!(value.as_limbs()[0].to_word(), 7);
/// assert_eq!(LimbArray::<0>::zero().bit_len(), 0);
/// ```
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LimbArray<const N: usize>([Limb; N]);

impl<const N: usize> LimbArray<N> {
    /// Creates a value from exactly `N` little-endian limbs, preserving leading zeros.
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// assert_eq!(LimbArray::new([Limb::new(3)]).as_limbs(), &[Limb::new(3)]);
    /// ```
    pub const fn new(limbs: [Limb; N]) -> Self {
        Self(limbs)
    }

    /// Creates a value with all limbs set to zero.
    /// ```
    /// use tc_limb::LimbArray;
    /// assert!(LimbArray::<4>::zero().is_zero());
    /// ```
    pub const fn zero() -> Self {
        Self([Limb::new(0); N])
    }

    /// Borrows all little-endian limbs, preserving the fixed length.
    /// ```
    /// use tc_limb::LimbArray;
    /// assert_eq!(LimbArray::<3>::zero().as_limbs().len(), 3);
    /// ```
    pub const fn as_limbs(&self) -> &[Limb; N] {
        &self.0
    }

    /// Mutably borrows all limbs; the array length remains fixed at `N`, with no signed interpretation.
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// let mut value = LimbArray::<2>::zero();
    /// value.as_mut_limbs()[0] = Limb::new(7);
    /// assert_eq!(value.as_limbs()[0].to_word(), 7);
    /// ```
    pub const fn as_mut_limbs(&mut self) -> &mut [Limb; N] {
        &mut self.0
    }

    /// Returns all little-endian limbs by value.
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// assert_eq!(LimbArray::<2>::zero().into_limbs(), [Limb::new(0); 2]);
    /// ```
    pub const fn into_limbs(self) -> [Limb; N] {
        self.0
    }

    /// Returns the fixed-width sum and the carry flag from the highest limb.
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// let max = LimbArray::new([Limb::new(Word::MAX)]);
    /// assert_eq!(max.add(&LimbArray::new([Limb::new(1)])), (LimbArray::zero(), true));
    /// ```
    pub fn add(&self, rhs: &Self) -> (Self, bool) {
        let (value, overflow) = Self::add_words(&self.0, &rhs.0);
        (Self(value), overflow)
    }

    /// Returns the fixed-width difference and the final borrow flag after propagating through all limbs.
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// let one = LimbArray::new([Limb::new(1)]);
    /// assert_eq!(LimbArray::zero().sub(&one), (LimbArray::new([Limb::new(Word::MAX)]), true));
    /// ```
    pub fn sub(&self, rhs: &Self) -> (Self, bool) {
        let (value, overflow) = Self::sub_words(&self.0, &rhs.0);
        (Self(value), overflow)
    }

    /// Returns the low half of the product; the overflow flag is true when the high half is nonzero.
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// let max = LimbArray::new([Limb::new(Word::MAX)]);
    /// assert_eq!(max.mul(&max), (LimbArray::new([Limb::new(1)]), true));
    /// ```
    pub fn mul(&self, rhs: &Self) -> (Self, bool) {
        let (value, overflow) = Self::mul_words(&self.0, &rhs.0);
        (Self(value), overflow)
    }

    /// Returns the full product as `(low, high)`, with `N` limbs in each half.
    ///
    /// The full value is `low + high * 2^(N * Word::BITS)`.
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// let max = LimbArray::new([Limb::new(Word::MAX)]);
    /// assert_eq!(max.mul_wide(&max), (LimbArray::new([Limb::new(1)]),
    ///                                LimbArray::new([Limb::new(Word::MAX - 1)])));
    /// ```
    pub fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        let (low, high) = Self::mul_wide_words(&self.0, &rhs.0);
        (Self(low), Self(high))
    }

    /// Returns the low and high halves of the full square.
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// let x = LimbArray::new([Limb::new(7)]);
    /// assert_eq!(x.square_wide(), (LimbArray::new([Limb::new(49)]), LimbArray::zero()));
    /// ```
    pub fn square_wide(&self) -> (Self, Self) {
        let (low, high) = Self::square_wide_words(&self.0);
        (Self(low), Self(high))
    }

    /// Adds the full product to a double-width accumulator, returning an overflow flag beyond `2N` limbs.
    ///
    /// Updates `low` and `high` in place, retaining the result modulo `2^(2N * Word::BITS)` on overflow.
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// let x = LimbArray::new([Limb::new(3)]);
    /// let mut low = LimbArray::new([Limb::new(1)]);
    /// let mut high = LimbArray::zero();
    /// assert!(!x.mul_add_to(&x, &mut low, &mut high));
    /// assert_eq!(low.as_limbs()[0].to_word(), 10);
    /// ```
    pub fn mul_add_to(&self, rhs: &Self, low: &mut Self, high: &mut Self) -> bool {
        Self::mul_add_to_words(&self.0, &rhs.0, &mut low.0, &mut high.0)
    }

    /// Performs unsigned division, returning the quotient and remainder; control flow depends on the values.
    ///
    /// # Panics
    /// Panics if the divisor is zero, including when `N = 0`.
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// let a = LimbArray::new([Limb::new(17)]);
    /// let b = LimbArray::new([Limb::new(5)]);
    /// assert_eq!(a.div_rem(&b), (LimbArray::new([Limb::new(3)]), LimbArray::new([Limb::new(2)])));
    /// ```
    pub fn div_rem(&self, rhs: &Self) -> (Self, Self) {
        let (quotient, remainder) = Self::div_rem_words(&self.0, &rhs.0);
        (Self(quotient), Self(remainder))
    }

    /// Computes the remainder of a double-width unsigned value, with `self` as the low half and `high` as the high half.
    ///
    /// # Panics
    /// Panics if `modulus` is zero, including when `N = 0`. This method is not guaranteed to run in constant time.
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// let low = LimbArray::new([Limb::new(Word::MAX)]);
    /// let high = LimbArray::new([Limb::new(1)]);
    /// let modulus = LimbArray::new([Limb::new(2)]);
    /// assert_eq!(low.wide_rem(&high, &modulus), LimbArray::new([Limb::new(1)]));
    /// ```
    pub fn wide_rem(&self, high: &Self, modulus: &Self) -> Self {
        Self(Self::wide_rem_words(&self.0, &high.0, &modulus.0))
    }

    /// Returns the additive inverse modulo `2^(N * Word::BITS)`; a zero-width value remains zero.
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// assert_eq!(LimbArray::new([Limb::new(1)]).wrapping_neg(), LimbArray::new([Limb::new(Word::MAX)]));
    /// ```
    pub fn wrapping_neg(&self) -> Self {
        Self(Self::wrapping_neg_words(&self.0))
    }

    /// Computes the unsigned greatest common divisor, with `gcd(0, 0) = 0`; control flow depends on the values.
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// assert_eq!(LimbArray::new([Limb::new(12)]).gcd(&LimbArray::new([Limb::new(8)])),
    ///            LimbArray::new([Limb::new(4)]));
    /// ```
    pub fn gcd(&self, rhs: &Self) -> Self {
        Self(Self::gcd_words(&self.0, &rhs.0))
    }

    /// Returns the number of significant bits in the unsigned representation, or zero for zero.
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// assert_eq!(LimbArray::new([Limb::new(8)]).bit_len(), 4);
    /// ```
    pub fn bit_len(&self) -> usize {
        Self::bit_len_words(&self.0)
    }

    /// Reads a bit, with index zero denoting the least significant bit.
    ///
    /// # Panics
    /// Panics if the index exceeds the fixed width; a zero-width value has no valid indices.
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// let x = LimbArray::new([Limb::new(8)]);
    /// assert!(x.test_bit(3));
    /// assert!(!x.test_bit(0));
    /// ```
    pub fn test_bit(&self, index: usize) -> bool {
        Self::test_bit_words(&self.0, index)
    }

    /// Returns whether all limbs are zero; true for zero width. This comparison may exit early.
    /// ```
    /// use tc_limb::LimbArray;
    /// assert!(LimbArray::<0>::zero().is_zero());
    /// ```
    pub fn is_zero(&self) -> bool {
        Self::is_zero_words(&self.0)
    }

    /// Returns whether the value equals one; false for zero width. This comparison may exit early.
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// assert!(LimbArray::new([Limb::new(1), Limb::new(0)]).is_one());
    /// ```
    pub fn is_one(&self) -> bool {
        Self::is_one_words(&self.0)
    }

    /// Shifts right logically by one bit in place, discarding the lowest bit; zero width is unchanged.
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// let mut x = LimbArray::new([Limb::new(7)]);
    /// x.shr_one();
    /// assert_eq!(x.as_limbs()[0].to_word(), 3);
    /// ```
    pub fn shr_one(&mut self) {
        Self::shr_one_words(&mut self.0);
    }

    /// Shifts left by one bit in place and returns the highest bit shifted out; false for zero width.
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// let mut x = LimbArray::new([Limb::new(1 << (Word::BITS - 1))]);
    /// assert!(x.shl_one());
    /// assert!(x.is_zero());
    /// ```
    pub fn shl_one(&mut self) -> bool {
        Self::shl_one_words(&mut self.0)
    }
}

impl<const N: usize> Default for LimbArray<N> {
    fn default() -> Self {
        Self::zero()
    }
}

/// Compares unsigned values starting at the highest limb, with possible early exit.
/// ```
/// use tc_limb::{Limb, LimbArray};
/// use core::cmp::Ordering;
/// let a = LimbArray::new([Limb::new(9), Limb::new(0)]);
/// let b = LimbArray::new([Limb::new(0), Limb::new(1)]);
/// assert_eq!(a.cmp(&b), Ordering::Less);
/// ```
impl<const N: usize> Ord for LimbArray<N> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        Self::cmp_words(&self.0, &rhs.0)
    }
}
impl<const N: usize> PartialOrd for LimbArray<N> {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

/// Selects limb by limb without branching on input values; zero selects `a`, and one selects `b`.
/// ```
/// use tc_limb::{Choice, ConditionallySelectable, Limb, LimbArray};
/// let a = LimbArray::<1>::zero();
/// let b = LimbArray::new([Limb::new(7)]);
/// assert_eq!(LimbArray::conditional_select(&a, &b, Choice::from_lsb(1)), b);
/// ```
impl<const N: usize> ConditionallySelectable for LimbArray<N> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<[Limb; N]>::conditional_select(&a.0, &b.0, choice))
    }
}

/// Compares all `N` limbs without early exit; two zero-width values are equal.
/// ```
/// use tc_limb::{ConstantTimeEq, LimbArray};
/// assert_eq!(LimbArray::<0>::zero().ct_eq(&LimbArray::zero()).unwrap_u8(), 1);
/// ```
impl<const N: usize> ConstantTimeEq for LimbArray<N> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.0.ct_eq(&rhs.0)
    }
}
