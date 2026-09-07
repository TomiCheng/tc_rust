//! Contracts for constant-time comparison and conditional updates.

use crate::Choice;

/// Selects without branches or addresses depending on the choice or values.
///
/// Implementations must preserve this contract for both possible choices.
/// Composite types can select each field through its own implementation.
///
/// ```
/// use tc_constant_time::{Choice, ConditionallySelectable};
///
/// #[derive(Debug, PartialEq)]
/// struct Pair(u32, u64);
///
/// impl ConditionallySelectable for Pair {
///     fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
///         Self(
///             u32::conditional_select(&a.0, &b.0, choice),
///             u64::conditional_select(&a.1, &b.1, choice),
///         )
///     }
/// }
///
/// let a = Pair(3, 5);
/// let b = Pair(7, 11);
/// assert_eq!(Pair::conditional_select(&a, &b, Choice::from_lsb(0)), a);
/// assert_eq!(Pair::conditional_select(&a, &b, Choice::from_lsb(1)), b);
/// ```
pub trait ConditionallySelectable: Sized {
    /// Returns `a` for zero and `b` for one.
    ///
    /// The inputs are borrowed and remain unchanged. Fixed-size arrays apply
    /// the same choice to every element.
    ///
    /// ```
    /// use tc_constant_time::{Choice, ConditionallySelectable};
    ///
    /// let a = [1_u8, 2];
    /// let b = [3_u8, 4];
    /// assert_eq!(<[u8; 2]>::conditional_select(&a, &b, Choice::from_lsb(0)), a);
    /// assert_eq!(<[u8; 2]>::conditional_select(&a, &b, Choice::from_lsb(1)), b);
    /// assert_eq!(usize::conditional_select(&0, &usize::MAX, Choice::from_lsb(1)), usize::MAX);
    /// ```
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self;

    /// Assigns `other` for one; leaves `self` unchanged for zero.
    ///
    /// The default supports types without `Copy` or `Clone`. Integer and array
    /// implementations override it to update storage in place.
    ///
    /// ```
    /// use tc_constant_time::{Choice, ConditionallySelectable};
    /// let mut value = [1_u32, 2];
    /// value.conditional_assign(&[3, 4], Choice::from_lsb(0));
    /// assert_eq!(value, [1, 2]);
    /// value.conditional_assign(&[3, 4], Choice::from_lsb(1));
    /// assert_eq!(value, [3, 4]);
    /// ```
    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        *self = Self::conditional_select(self, other, choice);
    }

    /// Swaps `a` and `b` for one; leaves both unchanged for zero.
    ///
    /// ```
    /// use tc_constant_time::{Choice, ConditionallySelectable};
    /// let (mut a, mut b) = (i32::MIN, i32::MAX);
    /// i32::conditional_swap(&mut a, &mut b, Choice::from_lsb(1));
    /// assert_eq!((a, b), (i32::MAX, i32::MIN));
    /// ```
    fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        let selected_a = Self::conditional_select(a, b, choice);
        let selected_b = Self::conditional_select(b, a, choice);
        *a = selected_a;
        *b = selected_b;
    }
}
/// Equality without early exits on secret values.
///
/// Implementations must avoid input-dependent branches and memory addresses.
/// For composite values, compare every field and combine the resulting choices
/// with `&`; do not reveal a result to short-circuit the remaining comparisons.
/// Slice lengths are public: mismatched lengths return zero immediately.
///
/// ```
/// use tc_constant_time::{Choice, ConstantTimeEq};
///
/// struct Pair(u32, u64);
///
/// impl ConstantTimeEq for Pair {
///     fn ct_eq(&self, rhs: &Self) -> Choice {
///         self.0.ct_eq(&rhs.0) & self.1.ct_eq(&rhs.1)
///     }
/// }
///
/// let value = Pair(3, 5);
/// assert_eq!(value.ct_eq(&Pair(3, 5)).unwrap_u8(), 1);
/// assert_eq!(value.ct_eq(&Pair(3, 7)).unwrap_u8(), 0);
/// ```
pub trait ConstantTimeEq {
    /// Returns a one choice for equal values and a zero choice otherwise.
    ///
    /// Array comparisons visit all elements, even after a mismatch. Empty
    /// arrays compare equal.
    ///
    /// ```
    /// use tc_constant_time::ConstantTimeEq;
    ///
    /// assert_eq!(0_u8.ct_eq(&u8::MAX).unwrap_u8(), 0);
    /// assert_eq!(u32::MAX.ct_eq(&u32::MAX).unwrap_u8(), 1);
    /// assert_eq!([1_u64, 2].ct_eq(&[1, 3]).unwrap_u8(), 0);
    /// assert_eq!(usize::MAX.ct_eq(&usize::MAX).unwrap_u8(), 1);
    /// ```
    fn ct_eq(&self, rhs: &Self) -> Choice;
}

/// Conditionally negates a value with wrapping arithmetic.
///
/// Integer implementations leave the value unchanged for zero and negate it
/// modulo its bit width for one. Signed minimum values remain unchanged when
/// negated. Arrays apply the operation to every element.
///
/// ```
/// use tc_constant_time::{Choice, ConditionallyNegatable};
/// let mut value = 3_u8;
/// value.conditional_negate(Choice::from_lsb(1));
/// assert_eq!(value, 253);
/// let mut minimum = i32::MIN;
/// minimum.conditional_negate(Choice::from_lsb(1));
/// assert_eq!(minimum, i32::MIN);
/// ```
pub trait ConditionallyNegatable {
    /// Negates in place for one; leaves the value unchanged for zero.
    fn conditional_negate(&mut self, choice: Choice);
}

/// Numeric ordering without value-dependent branches or addresses.
///
/// Implemented for all primitive signed and unsigned integer types, following
/// each type's numeric order. Arrays and slices have no ordering implementation
/// in this crate.
///
/// ```
/// use tc_constant_time::ConstantTimeOrd;
/// assert_eq!(0_u128.ct_lt(&u128::MAX).unwrap_u8(), 1);
/// assert_eq!(u128::MAX.ct_gt(&0).unwrap_u8(), 1);
/// assert_eq!(7_u16.ct_le(&7).unwrap_u8(), 1);
/// assert_eq!(7_u16.ct_ge(&8).unwrap_u8(), 0);
/// ```
///
/// Signed comparisons order negative values before zero and positive values,
/// including the minimum and maximum values without arithmetic overflow.
///
/// ```
/// use tc_constant_time::ConstantTimeOrd;
/// assert_eq!(i8::MIN.ct_lt(&i8::MAX).unwrap_u8(), 1);
/// assert_eq!((-1_i16).ct_lt(&0).unwrap_u8(), 1);
/// assert_eq!(0_i32.ct_gt(&-1).unwrap_u8(), 1);
/// assert_eq!((-7_i64).ct_le(&-7).unwrap_u8(), 1);
/// assert_eq!(i128::MAX.ct_ge(&i128::MIN).unwrap_u8(), 1);
/// assert_eq!(isize::MIN.ct_lt(&0).unwrap_u8(), 1);
/// ```
pub trait ConstantTimeOrd: ConstantTimeEq {
    /// Returns one when `self < rhs`, and zero otherwise.
    fn ct_lt(&self, rhs: &Self) -> Choice;

    /// Returns one when `self > rhs`, and zero otherwise.
    fn ct_gt(&self, rhs: &Self) -> Choice {
        rhs.ct_lt(self)
    }

    /// Returns one when `self <= rhs`, and zero otherwise.
    fn ct_le(&self, rhs: &Self) -> Choice {
        !self.ct_gt(rhs)
    }

    /// Returns one when `self >= rhs`, and zero otherwise.
    fn ct_ge(&self, rhs: &Self) -> Choice {
        !self.ct_lt(rhs)
    }
}
