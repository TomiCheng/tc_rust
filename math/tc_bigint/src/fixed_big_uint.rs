//! Fixed-precision unsigned integers without allocation.

#[cfg(test)]
use crate::ConversionError;
use crate::traits::{Bounded, One, Unsigned, Zero};
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
mod pow;
mod shl;
mod shr;
mod str;
mod sub;

/// An unsigned integer containing exactly `N` little-endian limbs.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FixedBigUint<const N: usize> {
    limbs: crate::LimbArray<N>,
}

impl<const N: usize> FixedBigUint<N> {
    /// Lowest representable value.
    pub const MIN: Self = Self::zero();

    /// Highest representable value.
    pub const MAX: Self = Self {
        limbs: crate::LimbArray::new([Limb::new(Word::MAX); N]),
    };

    pub(crate) const fn from_limbs(limbs: [Limb; N]) -> Self {
        Self {
            limbs: crate::LimbArray::new(limbs),
        }
    }

    pub(crate) const fn into_limbs(self) -> [Limb; N] {
        self.limbs.into_limbs()
    }

    /// 由兩個半寬值接成全寬值，低位在前。
    ///
    /// 要求 `N == 2 * H`。寬度是公開參數，因此此斷言不洩漏秘密。
    pub fn concat<const H: usize>(low: &FixedBigUint<H>, high: &FixedBigUint<H>) -> Self {
        assert!(N == 2 * H, "destination width must be twice the half width");
        let mut limbs = [Limb::new(0); N];
        limbs[..H].copy_from_slice(low.as_limbs());
        limbs[H..].copy_from_slice(high.as_limbs());
        Self::from_limbs(limbs)
    }

    /// 將較窄的值以高位補零擴展到此寬度。
    ///
    /// 要求 `N >= H`。寬度是公開參數，因此此斷言不洩漏秘密。
    pub fn widen_from<const H: usize>(value: &FixedBigUint<H>) -> Self {
        assert!(
            N >= H,
            "destination width must not be narrower than source width"
        );
        let mut limbs = [Limb::new(0); N];
        limbs[..H].copy_from_slice(value.as_limbs());
        Self::from_limbs(limbs)
    }

    /// Returns zero.
    pub const fn zero() -> Self {
        Self {
            limbs: crate::LimbArray::new([Limb::new(0); N]),
        }
    }

    /// Returns the minimum representable value.
    pub const fn min_value() -> Self {
        Self::MIN
    }

    /// Returns the maximum representable value.
    pub const fn max_value() -> Self {
        Self::MAX
    }

    /// Borrows all little-endian limbs, including high zero limbs.
    pub const fn as_limbs(&self) -> &[Limb; N] {
        self.limbs.as_limbs()
    }

    /// Returns whether this value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.as_limbs().iter().all(|word| word.to_word() == 0)
    }

    fn checked_u128(&self) -> Option<u128> {
        let mut result = 0_u128;
        for (index, word) in self.limbs.as_limbs().iter().enumerate() {
            let shift = index * Word::BITS as usize;
            if shift >= 128 {
                if word.to_word() != 0 {
                    return None;
                }
            } else {
                result |= (word.to_word() as u128) << shift;
            }
        }
        Some(result)
    }
}

impl<const N: usize> Default for FixedBigUint<N> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<const N: usize> Bounded for FixedBigUint<N> {
    const MIN: Self = Self::MIN;
    const MAX: Self = Self::MAX;
}

impl<const N: usize> Zero for FixedBigUint<N> {
    fn zero() -> Self {
        Self::zero()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl<const N: usize> One for FixedBigUint<N> {
    fn one() -> Self {
        Self::from(1_u8)
    }
}

impl<const N: usize> Unsigned for FixedBigUint<N> {}

#[cfg(test)]
mod tests;
