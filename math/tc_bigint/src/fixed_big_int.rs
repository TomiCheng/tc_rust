//! Fixed-precision signed integers without allocation.

use core::cmp::Ordering;

#[cfg(test)]
use crate::ConversionError;
use crate::traits::{Bounded, One, ToPrimitive, Zero};
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

/// A signed two's-complement integer containing exactly `N` little-endian limbs.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FixedBigInt<const N: usize> {
    limbs: crate::LimbArray<N>,
}

impl<const N: usize> FixedBigInt<N> {
    /// Lowest representable value.
    pub const MIN: Self = {
        let mut limbs = [Limb::new(0); N];
        if N != 0 {
            limbs[N - 1] = Limb::new(1 << (Word::BITS - 1));
        }
        Self {
            limbs: crate::LimbArray::new(limbs),
        }
    };

    /// Highest representable value.
    pub const MAX: Self = {
        let mut limbs = [Limb::new(Word::MAX); N];
        if N != 0 {
            limbs[N - 1] = Limb::new(Word::MAX >> 1);
        }
        Self {
            limbs: crate::LimbArray::new(limbs),
        }
    };

    pub(crate) const fn from_limbs(limbs: [Limb; N]) -> Self {
        Self {
            limbs: crate::LimbArray::new(limbs),
        }
    }

    /// Returns zero.
    pub const fn zero() -> Self {
        Self::from_limbs([Limb::new(0); N])
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
    pub(crate) const fn as_limbs(&self) -> &[Limb; N] {
        self.limbs.as_limbs()
    }

    /// Returns whether the value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.as_limbs().iter().all(|word| word.to_word() == 0)
    }

    pub(crate) fn magnitude(&self) -> [Limb; N] {
        if self.is_negative() {
            self.limbs.wrapping_neg().into_limbs()
        } else {
            self.limbs.into_limbs()
        }
    }

    // Sign interpretation belongs to the signed integer layer; the underlying LimbArray remains unsigned.
    pub(crate) fn is_negative_limbs(words: &[Limb; N]) -> bool {
        words
            .last()
            .is_some_and(|word| word.to_word() >> (Word::BITS - 1) != 0)
    }

    fn from_sign_magnitude(negative: bool, magnitude: [Limb; N]) -> Option<Self> {
        let min_magnitude = Self::min_value().limbs.into_limbs();
        if negative {
            if crate::LimbArray::new(magnitude).cmp(&crate::LimbArray::new(min_magnitude))
                == Ordering::Greater
            {
                return None;
            }
            Some(Self {
                limbs: crate::LimbArray::new(
                    crate::LimbArray::new(magnitude).wrapping_neg().into_limbs(),
                ),
            })
        } else {
            if FixedBigInt::is_negative_limbs(&magnitude) {
                return None;
            }
            Some(Self {
                limbs: crate::LimbArray::new(magnitude),
            })
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

#[cfg(test)]
mod tests;
