//! Exponentiation for [`FixedBigUint`].

use crate::traits::{ModPow, One, Pow};
use crate::{FixedBigUint, arithmetic};

impl<const N: usize> FixedBigUint<N> {
    /// Returns `self^exponent mod modulus`.
    pub fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        Self {
            limbs: arithmetic::fixed_mod_pow(&self.limbs, &exponent.limbs, &modulus.limbs),
        }
    }
}

impl<const N: usize> Pow<u32> for FixedBigUint<N> {
    type Output = Self;
    fn pow(self, mut exponent: u32) -> Self {
        let mut base = self;
        let mut result = Self::one();
        while exponent != 0 {
            if exponent & 1 != 0 {
                result *= base;
            }
            exponent >>= 1;
            if exponent != 0 {
                base *= base;
            }
        }
        result
    }
}

impl<const N: usize> Pow<&u32> for FixedBigUint<N> {
    type Output = Self;
    fn pow(self, exponent: &u32) -> Self {
        Pow::pow(self, *exponent)
    }
}

impl<const N: usize> Pow<u32> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;
    fn pow(self, exponent: u32) -> Self::Output {
        Pow::pow(*self, exponent)
    }
}

impl<const N: usize> Pow<&u32> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;
    fn pow(self, exponent: &u32) -> Self::Output {
        Pow::pow(*self, *exponent)
    }
}

impl<const N: usize> ModPow for FixedBigUint<N> {
    type Output = Self;
    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        FixedBigUint::mod_pow(self, exponent, modulus)
    }
}
