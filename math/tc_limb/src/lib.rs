#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
//! Fixed-width, little-endian limb arithmetic.
//!
//! This crate provides [`Limb`] for single-word operations and
//! [`LimbArray`] for unsigned, fixed-width arithmetic. It is `no_std`, does not
//! allocate, and does not assign a signed interpretation to the highest bit.
//!
//! # Representation
//!
//! A `LimbArray<N>` contains exactly `N` limbs in little-endian order: array
//! index zero holds the least significant word. Its width is
//! `N * Word::BITS` bits. [`Word`] is `u64` on 64-bit targets and `u32` on
//! 16-bit and 32-bit targets, so callers must define portable serialization
//! formats explicitly instead of treating the native limb layout as one.
//! Operations require operands with the same limb count; no implicit extension
//! or truncation is performed.
//!
//! # Arithmetic
//!
//! Operations on `LimbArray` preserve the fixed width. Addition and
//! subtraction return the truncated result together with the final carry or
//! borrow, while wide multiplication returns separate low and high halves.
//!
//! ```
//! use tc_limb::{Limb, LimbArray, Word};
//!
//! let max = LimbArray::new([Limb::new(Word::MAX); 2]);
//! let one = LimbArray::new([Limb::new(1), Limb::new(0)]);
//!
//! let (sum, carry) = max.add(&one);
//! assert!(sum.is_zero());
//! assert!(carry);
//!
//! let (low, high) = max.mul_wide(&one);
//! assert_eq!(low, max);
//! assert!(high.is_zero());
//! ```
//!
//! [`Limb`] intentionally implements no arithmetic, bitwise, or shift traits
//! from `core::ops`. Use its named methods when their overflow behavior matches
//! the operation, or explicitly convert through [`Limb::to_word`] and
//! [`Limb::new`] when native [`Word`] semantics are required.
//!
//! # Bit indexing
//!
//! Bit indices are also little-endian: index zero denotes the least significant
//! bit, and valid indices are less than `N * Word::BITS`.
//!
//! ```
//! use tc_limb::{Limb, LimbArray, Word};
//!
//! let index = Word::BITS as usize;
//! let value = LimbArray::<2>::zero().set_bit(index);
//! assert!(value.test_bit(index));
//! assert_eq!(value.as_limbs()[1], Limb::new(1));
//! ```
//!
//! # Constant-time operations
//!
//! [`Limb`] and [`LimbArray`] implement [`ConditionallySelectable`] and
//! [`ConstantTimeEq`]. These implementations do not branch on the choice bit or
//! operand values and, for arrays, inspect every limb. The public array length
//! `N` may still affect execution time.
//!
//! ```
//! use tc_limb::{Choice, ConditionallySelectable, ConstantTimeEq, Limb, LimbArray};
//!
//! let a = LimbArray::new([Limb::new(3)]);
//! let b = LimbArray::new([Limb::new(9)]);
//! let selected = LimbArray::conditional_select(&a, &b, Choice::from_lsb(1));
//! assert_eq!(selected.ct_eq(&b).unwrap_u8(), 1);
//! ```
//!
//! Other operations, including ordinary equality, ordering, zero checks,
//! arithmetic, division, and greatest-common-divisor calculation, make no
//! constant-time guarantee. Revealing a [`Choice`] with
//! [`Choice::unwrap_u8`] also exposes the comparison result.

mod limb;
mod limb_array;

pub use limb::{Limb, WideWord, Word};
pub use limb_array::LimbArray;
pub use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
