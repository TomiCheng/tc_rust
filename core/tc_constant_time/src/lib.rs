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
mod integers;
mod slice;
mod traits;

pub use choice::Choice;
pub use slice::fixed_time_eq;
pub use traits::{
    ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, ConstantTimeOrd,
};

#[cfg(test)]
mod tests;
