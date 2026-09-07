#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
//! Fixed-width conditional selection and equality without heap allocation.
//!
//! [`Choice`] holds one bit. [`ConditionallySelectable`] chooses between two
//! values, and [`ConstantTimeEq`] compares them without an early exit on a
//! mismatch. Both traits are implemented for `u8`, `u32`, `u64`, and `usize`,
//! and for fixed-size arrays whose elements implement the corresponding trait.
//! The crate is `no_std` and has no dependencies or feature flags.
//!
//! # Selecting and comparing
//!
//! A zero choice selects the first argument; a one choice selects the second.
//! Keep intermediate results as `Choice` values when combining predicates.
//! Calling [`Choice::unwrap_u8`] exposes the bit for ordinary control flow.
//!
//! ```
//! use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
//!
//! let expected = [1_u8, 2, 3, 4];
//! let received = [1_u8, 2, 3, 4];
//! let enabled = Choice::from_lsb(1);
//! let accept = expected.ct_eq(&received) & enabled;
//! let selected = <[u8; 4]>::conditional_select(&[0; 4], &received, accept);
//! assert_eq!(selected, received);
//! assert_eq!(accept.unwrap_u8(), 1);
//! ```
//!
//! Arrays retain their length and process every element. Two empty arrays
//! compare equal, and selecting between them produces an empty array.
//!
//! ```
//! use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
//!
//! let empty: [u32; 0] = [];
//! assert_eq!(empty.ct_eq(&empty).unwrap_u8(), 1);
//! assert_eq!(<[u32; 0]>::conditional_select(&empty, &empty, Choice::from_lsb(1)), empty);
//! ```
//!
//! # Timing contract
//!
//! Trait implementations must avoid control flow and memory addresses that
//! depend on secret input values. Public sizes, including array length, may
//! affect execution time. Array implementations inherit the timing properties
//! of their element implementations.
//!
//! The built-in operations use integer masks and full array scans.
//! [`core::hint::black_box`] is a best-effort optimization barrier, not a
//! guarantee of constant-time machine code. Review generated code for the
//! target compiler and hardware before relying on timing properties. Ordinary
//! comparisons or branches after revealing a `Choice` are outside this contract.

/// A one-bit value for masked selection and composable predicates.
///
/// Construct a choice with [`Self::from_lsb`], which keeps only the input's
/// least significant bit. Combine choices with `!`, `&`, and `|` without first
/// revealing them. There is no implicit conversion to `bool`; use
/// [`Self::unwrap_u8`] when the bit may be exposed.
///
/// ```
/// use tc_constant_time::Choice;
///
/// let yes = Choice::from_lsb(1);
/// let no = Choice::from_lsb(0);
/// assert_eq!((!yes).unwrap_u8(), 0);
/// assert_eq!((yes & no).unwrap_u8(), 0);
/// assert_eq!((yes | no).unwrap_u8(), 1);
/// ```
#[derive(Clone, Copy)]
pub struct Choice(u8);
impl Choice {
    /// Keeps the least significant bit and passes it through an optimization barrier.
    ///
    /// Every `u8` is accepted: even inputs produce zero, and odd inputs produce
    /// one. This is not a test for whether the input is nonzero.
    ///
    /// ```
    /// use tc_constant_time::Choice;
    ///
    /// assert_eq!(Choice::from_lsb(0).unwrap_u8(), 0);
    /// assert_eq!(Choice::from_lsb(2).unwrap_u8(), 0);
    /// assert_eq!(Choice::from_lsb(3).unwrap_u8(), 1);
    /// assert_eq!(Choice::from_lsb(255).unwrap_u8(), 1);
    /// ```
    #[inline(always)]
    pub fn from_lsb(value: u8) -> Self {
        Self(core::hint::black_box(value & 1))
    }
    /// Reveals the bit as zero or one.
    ///
    /// Branching on this result can expose the choice through control flow.
    /// Keep it as a [`Choice`] until that disclosure is intentional.
    ///
    /// ```
    /// use tc_constant_time::ConstantTimeEq;
    ///
    /// let equal = 42_u64.ct_eq(&42);
    /// let revealed: u8 = equal.unwrap_u8();
    /// assert_eq!(revealed, 1);
    /// ```
    #[inline(always)]
    pub fn unwrap_u8(self) -> u8 {
        self.0
    }
}
impl core::ops::Not for Choice {
    type Output = Self;
    fn not(self) -> Self {
        Self::from_lsb(self.0 ^ 1)
    }
}
impl core::ops::BitAnd for Choice {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self::from_lsb(self.0 & rhs.0)
    }
}
impl core::ops::BitOr for Choice {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self::from_lsb(self.0 | rhs.0)
    }
}

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
}
/// Equality without early exits on secret values.
///
/// Implementations must avoid input-dependent branches and memory addresses.
/// For composite values, compare every field and combine the resulting choices
/// with `&`; do not reveal a result to short-circuit the remaining comparisons.
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

macro_rules! integers {
    ($($t:ty),*) => {$ (
        impl ConditionallySelectable for $t {
            #[inline(always)]
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                let mask = (0 as $t).wrapping_sub(choice.0 as $t);
                a ^ ((a ^ b) & mask)
            }
        }
        impl ConstantTimeEq for $t {
            #[inline(always)]
            fn ct_eq(&self, rhs: &Self) -> Choice {
                let difference = self ^ rhs;
                Choice::from_lsb((((difference | difference.wrapping_neg()) >> (<$t>::BITS - 1)) ^ 1) as u8)
            }
        }
    )*};
}
integers!(u8, u32, u64, usize);
impl<T: ConditionallySelectable, const N: usize> ConditionallySelectable for [T; N] {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        core::array::from_fn(|i| T::conditional_select(&a[i], &b[i], choice))
    }
}
impl<T: ConstantTimeEq, const N: usize> ConstantTimeEq for [T; N] {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        let mut equal = Choice::from_lsb(1);
        for i in 0..N {
            equal = equal & self[i].ct_eq(&rhs[i]);
        }
        equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn select_and_equal_all_bytes() {
        for a in 0..=255_u8 {
            for b in 0..=255_u8 {
                assert_eq!(u8::conditional_select(&a, &b, Choice::from_lsb(0)), a);
                assert_eq!(u8::conditional_select(&a, &b, Choice::from_lsb(1)), b);
                assert_eq!(a.ct_eq(&b).unwrap_u8(), (a == b) as u8);
            }
        }
    }

    #[test]
    fn choice_normalizes_every_byte_and_combines_bits() {
        for value in 0..=u8::MAX {
            let choice = Choice::from_lsb(value);
            assert_eq!(choice.unwrap_u8(), value & 1);
            assert_eq!((!choice).unwrap_u8(), (value & 1) ^ 1);
            for bit in 0..=1 {
                let rhs = Choice::from_lsb(bit);
                assert_eq!((choice & rhs).unwrap_u8(), (value & 1) & bit);
                assert_eq!((choice | rhs).unwrap_u8(), (value & 1) | bit);
            }
        }
    }

    macro_rules! wide_integer_tests {
        ($name:ident, $word:ty) => {
            #[test]
            fn $name() {
                for bit in 0..<$word>::BITS {
                    let single = (1 as $word) << bit;
                    let values = [0, 1, single, !single, <$word>::MAX];
                    for a in values {
                        for b in values {
                            assert_eq!(<$word>::conditional_select(&a, &b, Choice::from_lsb(0)), a);
                            assert_eq!(<$word>::conditional_select(&a, &b, Choice::from_lsb(1)), b);
                            assert_eq!(a.ct_eq(&b).unwrap_u8(), u8::from(a == b));
                        }
                    }
                }
            }
        };
    }

    wide_integer_tests!(select_and_equal_u32_bit_boundaries, u32);
    wide_integer_tests!(select_and_equal_u64_bit_boundaries, u64);
    wide_integer_tests!(select_and_equal_usize_bit_boundaries, usize);

    #[test]
    fn arrays_select_and_compare_every_position() {
        let original = [0_u64, 1, 1 << 63, u64::MAX];
        assert_eq!(original.ct_eq(&original).unwrap_u8(), 1);
        for index in 0..original.len() {
            let mut changed = original;
            changed[index] ^= 1;
            assert_eq!(original.ct_eq(&changed).unwrap_u8(), 0);
            assert_eq!(changed.ct_eq(&original).unwrap_u8(), 0);
            assert_eq!(
                <[u64; 4]>::conditional_select(&original, &changed, Choice::from_lsb(0)),
                original
            );
            assert_eq!(
                <[u64; 4]>::conditional_select(&original, &changed, Choice::from_lsb(1)),
                changed
            );
        }
        let empty: [u64; 0] = [];
        assert_eq!(empty.ct_eq(&empty).unwrap_u8(), 1);
        for bit in 0..=1 {
            assert_eq!(
                <[u64; 0]>::conditional_select(&empty, &empty, Choice::from_lsb(bit)),
                empty
            );
        }
    }
}
