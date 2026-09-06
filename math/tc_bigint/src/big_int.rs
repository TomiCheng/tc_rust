//! Arbitrary-precision signed integers.

use alloc::vec::Vec;

#[cfg(test)]
use crate::ConversionError;
use crate::arithmetic;
use crate::encoding;
use crate::traits::{One, Zero};
use crate::{Limb, Word};

mod add;
mod array;
mod bit_and;
mod bit_not;
mod bit_or;
mod bit_xor;
mod bits;
mod cmp;
mod div;
mod from;
mod gcd;
mod invert_mod;
mod mul;
mod neg;
mod pow;
mod shl;
mod shr;
mod sign;
mod str;
mod sub;

/// A signed integer whose precision grows as needed.
///
/// Limbs are stored in canonical little-endian two's-complement form. Zero has
/// no limbs; other values have no redundant high sign-extension limbs.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct BigInt {
    limbs: Vec<Limb>,
}

impl BigInt {
    pub(crate) fn from_limbs(mut limbs: Vec<Limb>) -> Self {
        encoding::normalize_signed(&mut limbs);
        Self { limbs }
    }

    pub(crate) fn from_sign_magnitude(negative: bool, mut magnitude: Vec<Limb>) -> Self {
        arithmetic::normalize(&mut magnitude);
        if magnitude.is_empty() {
            return Self::default();
        }

        if !negative {
            if magnitude.last().expect("non-empty").to_word() >> (Word::BITS - 1) != 0 {
                magnitude.push(Limb::new(0));
            }
            return Self::from_limbs(magnitude);
        }

        for word in &mut magnitude {
            *word = Limb::new(!word.to_word());
        }
        arithmetic::add_small(&mut magnitude, 1);
        if magnitude.last().expect("non-empty").to_word() >> (Word::BITS - 1) == 0 {
            magnitude.push(Limb::new(Word::MAX));
        }
        Self::from_limbs(magnitude)
    }

    fn sign_magnitude(&self) -> (bool, Vec<Limb>) {
        if !self.is_negative() {
            let mut magnitude = self.limbs.clone();
            arithmetic::normalize(&mut magnitude);
            return (false, magnitude);
        }

        let mut magnitude: Vec<Limb> = self.limbs.iter().map(|word| Limb::new(!word.to_word())).collect();
        arithmetic::add_small(&mut magnitude, 1);
        arithmetic::normalize(&mut magnitude);
        (true, magnitude)
    }

    /// Borrows the canonical little-endian two's-complement limbs.
    pub fn as_limbs(&self) -> &[Limb] {
        &self.limbs
    }

    /// Returns whether the value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }
}

impl Zero for BigInt {
    fn zero() -> Self {
        Self::default()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl One for BigInt {
    fn one() -> Self {
        Self::from(1_u8)
    }
}

#[cfg(test)]
mod tests;
