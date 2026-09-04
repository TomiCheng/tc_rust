//! Fixed-precision signed integers without allocation.

use core::cmp::Ordering;

#[cfg(test)]
use crate::ConversionError;
use crate::arithmetic;
use crate::traits::{Bounded, Gcd, ModInverse, One, Signed, ToPrimitive, Zero};
use crate::{FixedBigUint, Limb, Word};

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

/// A signed two's-complement integer containing exactly `N` little-endian limbs.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FixedBigInt<const N: usize> {
    limbs: [Limb; N],
}

impl<const N: usize> FixedBigInt<N> {
    /// Lowest representable value.
    pub const MIN: Self = {
        let mut limbs = [Limb(0); N];
        if N != 0 {
            limbs[N - 1] = Limb(1 << (Word::BITS - 1));
        }
        Self { limbs }
    };

    /// Highest representable value.
    pub const MAX: Self = {
        let mut limbs = [Limb(Word::MAX); N];
        if N != 0 {
            limbs[N - 1] = Limb(Word::MAX >> 1);
        }
        Self { limbs }
    };

    pub(crate) const fn from_limbs(limbs: [Limb; N]) -> Self {
        Self { limbs }
    }

    /// Returns zero.
    pub const fn zero() -> Self {
        Self::from_limbs([Limb(0); N])
    }

    /// Returns the lowest representable signed value.
    pub const fn min_value() -> Self {
        Self::MIN
    }

    /// Returns the highest representable signed value.
    pub const fn max_value() -> Self {
        Self::MAX
    }

    /// Borrows all little-endian two's-complement limbs.
    pub const fn as_limbs(&self) -> &[Limb; N] {
        &self.limbs
    }

    /// Returns whether the value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|word| word.0 == 0)
    }

    /// Returns the non-negative greatest common divisor as an unsigned value.
    pub fn gcd(&self, other: &Self) -> FixedBigUint<N> {
        FixedBigUint::from_limbs(arithmetic::fixed_gcd(&self.magnitude(), &other.magnitude()))
    }

    /// Returns the modular multiplicative inverse, when it exists.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        assert!(modulus.is_positive(), "modulus must be positive");
        let value = self.rem_euclid(modulus);
        arithmetic::fixed_mod_inverse(&value.limbs, &modulus.limbs)
            .and_then(|limbs| Self::from_sign_magnitude(false, limbs))
    }

    fn magnitude(&self) -> [Limb; N] {
        arithmetic::fixed_abs(&self.limbs)
    }

    fn from_sign_magnitude(negative: bool, magnitude: [Limb; N]) -> Option<Self> {
        let min_magnitude = Self::min_value().limbs;
        if negative {
            if arithmetic::fixed_cmp(&magnitude, &min_magnitude) == Ordering::Greater {
                return None;
            }
            Some(Self {
                limbs: arithmetic::fixed_wrapping_neg(&magnitude),
            })
        } else {
            if arithmetic::fixed_is_negative(&magnitude) {
                return None;
            }
            Some(Self { limbs: magnitude })
        }
    }

    fn checked_i128(&self) -> Option<i128> {
        let magnitude = FixedBigUint::from_limbs(self.magnitude()).to_u128()?;
        if self.is_negative() {
            if magnitude == 1_u128 << 127 {
                Some(i128::MIN)
            } else {
                i128::try_from(magnitude).ok().map(|value| -value)
            }
        } else {
            i128::try_from(magnitude).ok()
        }
    }
}

impl<const N: usize> Default for FixedBigInt<N> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<const N: usize> Bounded for FixedBigInt<N> {
    const MIN: Self = Self::MIN;
    const MAX: Self = Self::MAX;
}

impl<const N: usize> Zero for FixedBigInt<N> {
    fn zero() -> Self {
        Self::zero()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl<const N: usize> One for FixedBigInt<N> {
    fn one() -> Self {
        Self::from(1_i8)
    }
}

impl<const N: usize> Gcd for FixedBigInt<N> {
    type Output = FixedBigUint<N>;

    fn gcd(&self, rhs: &Self) -> Self::Output {
        FixedBigInt::gcd(self, rhs)
    }
}

impl<const N: usize> ModInverse for FixedBigInt<N> {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        FixedBigInt::mod_inverse(self, modulus)
    }
}

#[cfg(test)]
mod tests;
