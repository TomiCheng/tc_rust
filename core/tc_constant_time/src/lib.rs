#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
//! Conditional selection, comparison, and masked updates without heap allocation.
//!
//! [`Choice`] holds one bit. [`ConditionallySelectable`] chooses between two
//! values, and [`ConstantTimeEq`] compares them without an early exit on a
//! mismatch. Both traits support unsigned integers, `i32`, `i64`, and fixed-size
//! arrays. Equality also supports slices with public lengths. [`ConstantTimeOrd`]
//! orders unsigned integers, and [`ConditionallyNegatable`] provides wrapping
//! negation. [`fixed_time_eq`] deliberately reveals a byte-slice comparison.
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

mod array;
mod choice;
mod slice;
mod traits;

pub use choice::Choice;
pub use traits::{
    ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, ConstantTimeOrd,
};

/// Compares byte slices and deliberately reveals the equality result.
///
/// Use this convenience function only when the verification result is intended
/// to be public, such as authentication-tag verification. For intermediate
/// secret predicates, use [`ConstantTimeEq::ct_eq`] and retain the [`Choice`].
///
/// Lengths are public: different lengths return `false` immediately. Equal
/// lengths scan every byte, without an early exit on a mismatch. Empty slices
/// compare equal. This contract does not hide slice lengths.
///
/// ```
/// use tc_constant_time::fixed_time_eq;
/// assert!(fixed_time_eq(b"tag", b"tag"));
/// assert!(!fixed_time_eq(b"tag", b"tam"));
/// assert!(!fixed_time_eq(b"tag", b"tag\0"));
/// assert!(fixed_time_eq(b"", b""));
/// ```
pub fn fixed_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}

macro_rules! integers {
    ($(($t:ty, $unsigned:ty)),*) => {$ (
        impl ConditionallySelectable for $t {
            #[inline(always)]
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                let mask = (0 as $t).wrapping_sub(choice.0 as $t);
                a ^ ((a ^ b) & mask)
            }

            #[inline(always)]
            fn conditional_assign(&mut self, other: &Self, choice: Choice) {
                let mask = (0 as $t).wrapping_sub(choice.0 as $t);
                *self ^= (*self ^ other) & mask;
            }

            #[inline(always)]
            fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
                let mask = (0 as $t).wrapping_sub(choice.0 as $t);
                let difference = (*a ^ *b) & mask;
                *a ^= difference;
                *b ^= difference;
            }
        }

        impl ConditionallyNegatable for $t {
            #[inline(always)]
            fn conditional_negate(&mut self, choice: Choice) {
                let mask = (0 as $t).wrapping_sub(choice.0 as $t);
                *self = (*self ^ mask).wrapping_sub(mask);
            }
        }

        impl ConstantTimeEq for $t {
            #[inline(always)]
            fn ct_eq(&self, rhs: &Self) -> Choice {
                // Cast before shifting: signed right shifts would propagate the sign bit.
                let difference = (*self ^ *rhs) as $unsigned;
                Choice::from_lsb((((difference | difference.wrapping_neg()) >> (<$unsigned>::BITS - 1)) ^ 1) as u8)
            }
        }
    )*};
}
integers!(
    (u8, u8),
    (u16, u16),
    (u32, u32),
    (u64, u64),
    (u128, u128),
    (usize, usize),
    (i32, u32),
    (i64, u64)
);

macro_rules! unsigned_ordering {
    ($($t:ty),*) => {$ (
        impl ConstantTimeOrd for $t {
            #[inline(always)]
            fn ct_lt(&self, rhs: &Self) -> Choice {
                let (x, y) = (*self, *rhs);
                // Hacker's Delight, section 2-12: borrow bit without a wider integer.
                let less = ((!x & y) | ((!x | y) & x.wrapping_sub(y))) >> (<$t>::BITS - 1);
                Choice::from_lsb(less as u8)
            }
        }
    )*};
}
unsigned_ordering!(u8, u16, u32, u64, u128, usize);

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

#[cfg(test)]
mod api_tests;
