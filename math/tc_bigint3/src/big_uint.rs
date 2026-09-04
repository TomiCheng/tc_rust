//! Arbitrary-precision unsigned integers.

use alloc::vec::Vec;

#[cfg(test)]
use crate::ConversionError;
use crate::arithmetic;
use crate::traits::{Gcd, ModInverse, One, Unsigned, Zero};
use crate::{BigInt, Limb};

mod add;
mod array;
mod bit_and;
// An unbounded unsigned integer has no finite-width bitwise complement.
mod bit_or;
mod bit_xor;
mod bits;
mod cmp;
mod div;
mod from;
mod mul;
mod pow;
mod shl;
mod shr;
mod str;
mod sub;

/// An unsigned integer whose precision grows as needed.
///
/// Limbs are stored from least significant to most significant. Zero has an
/// empty limb vector; non-zero values never contain redundant high zero limbs.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct BigUint {
    limbs: Vec<Limb>,
}

impl BigUint {
    pub(crate) fn from_limbs(mut limbs: Vec<Limb>) -> Self {
        arithmetic::normalize(&mut limbs);
        Self { limbs }
    }

    /// Borrows the canonical little-endian limbs.
    pub fn as_limbs(&self) -> &[Limb] {
        &self.limbs
    }

    /// Returns whether the value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    /// Returns the greatest common divisor.
    pub fn gcd(&self, other: &Self) -> Self {
        let mut left = self.clone();
        let mut right = other.clone();
        while !right.is_zero() {
            let remainder = &left % &right;
            left = right;
            right = remainder;
        }
        left
    }

    /// Returns the modular multiplicative inverse, when it exists.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        let value = BigInt::from_unsigned_le_u64(&self.to_le_u64());
        let modulus = BigInt::from_unsigned_le_u64(&modulus.to_le_u64());
        value
            .mod_inverse(&modulus)
            .map(|inverse| Self::from_le_u64(&inverse.to_le_u64()))
    }
}

impl Zero for BigUint {
    fn zero() -> Self {
        Self::default()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl One for BigUint {
    fn one() -> Self {
        Self::from(1_u8)
    }
}

impl Unsigned for BigUint {}

impl Gcd for BigUint {
    type Output = Self;

    fn gcd(&self, rhs: &Self) -> Self::Output {
        BigUint::gcd(self, rhs)
    }
}

impl ModInverse for BigUint {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        BigUint::mod_inverse(self, modulus)
    }
}

#[cfg(test)]
mod tests;
