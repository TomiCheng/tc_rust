//! Constant-time trait implementations for primitive integers.

use crate::{
    Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, ConstantTimeOrd,
};

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
    (i8, u8),
    (i16, u16),
    (i32, u32),
    (i64, u64),
    (i128, u128),
    (isize, usize)
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

macro_rules! signed_ordering {
    ($(($t:ty, $unsigned:ty)),*) => {$ (
        impl ConstantTimeOrd for $t {
            #[inline(always)]
            fn ct_lt(&self, rhs: &Self) -> Choice {
                // Flipping the sign bit maps signed order to unsigned order.
                let sign_bit = (1 as $unsigned) << (<$unsigned>::BITS - 1);
                let x = (*self as $unsigned) ^ sign_bit;
                let y = (*rhs as $unsigned) ^ sign_bit;
                x.ct_lt(&y)
            }
        }
    )*};
}
signed_ordering!(
    (i8, u8),
    (i16, u16),
    (i32, u32),
    (i64, u64),
    (i128, u128),
    (isize, usize)
);
