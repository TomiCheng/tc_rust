//! Arbitrary-precision signed integers.

use alloc::vec::Vec;

#[cfg(test)]
use crate::ConversionError;
use crate::arithmetic;
use crate::encoding;
use crate::traits::{Gcd, ModInverse, One, Signed, Zero};
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
            if magnitude.last().expect("non-empty").0 >> (Word::BITS - 1) != 0 {
                magnitude.push(Limb(0));
            }
            return Self::from_limbs(magnitude);
        }

        for word in &mut magnitude {
            word.0 = !word.0;
        }
        arithmetic::add_small(&mut magnitude, 1);
        if magnitude.last().expect("non-empty").0 >> (Word::BITS - 1) == 0 {
            magnitude.push(Limb(Word::MAX));
        }
        Self::from_limbs(magnitude)
    }

    fn sign_magnitude(&self) -> (bool, Vec<Limb>) {
        if !self.is_negative() {
            let mut magnitude = self.limbs.clone();
            arithmetic::normalize(&mut magnitude);
            return (false, magnitude);
        }

        let mut magnitude: Vec<Limb> = self.limbs.iter().map(|word| Limb(!word.0)).collect();
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

    /// Returns the non-negative greatest common divisor.
    pub fn gcd(&self, other: &Self) -> Self {
        let mut left = self.abs();
        let mut right = other.abs();
        while !right.is_zero() {
            let remainder = &left % &right;
            left = right;
            right = remainder;
        }
        left
    }

    /// Returns the modular multiplicative inverse, when it exists.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        assert!(modulus.is_positive(), "modulus must be positive");
        let mut old_remainder = modulus.clone();
        let mut remainder = self.rem_euclid(modulus);
        let mut old_coefficient = Self::zero();
        let mut coefficient = Self::one();

        while !remainder.is_zero() {
            let quotient = &old_remainder / &remainder;
            let next_remainder = &old_remainder - &quotient * &remainder;
            let next_coefficient = &old_coefficient - &quotient * &coefficient;
            old_remainder = remainder;
            remainder = next_remainder;
            old_coefficient = coefficient;
            coefficient = next_coefficient;
        }

        (old_remainder == Self::one()).then(|| old_coefficient.rem_euclid(modulus))
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

impl Gcd for BigInt {
    type Output = Self;

    fn gcd(&self, rhs: &Self) -> Self::Output {
        BigInt::gcd(self, rhs)
    }
}

impl ModInverse for BigInt {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        BigInt::mod_inverse(self, modulus)
    }
}

#[cfg(test)]
mod tests;
