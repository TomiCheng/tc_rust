//! Exponentiation for [`BigUint`].

use crate::traits::{One, Pow};
use crate::{BigUint, modular};

impl BigUint {
    /// Returns `self^exponent mod modulus`.
    pub fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        Self::from_limbs(modular::mod_pow(
            &self.limbs,
            &exponent.limbs,
            &modulus.limbs,
        ))
    }
}

impl Pow<u32> for BigUint {
    type Output = Self;

    fn pow(self, mut exponent: u32) -> Self {
        let mut base = self;
        let mut result = Self::one();
        while exponent != 0 {
            if exponent & 1 != 0 {
                result *= &base;
            }
            exponent >>= 1;
            if exponent != 0 {
                base = &base * &base;
            }
        }
        result
    }
}

impl Pow<&u32> for BigUint {
    type Output = Self;
    fn pow(self, exponent: &u32) -> Self {
        Pow::pow(self, *exponent)
    }
}

impl Pow<u32> for &BigUint {
    type Output = BigUint;
    fn pow(self, exponent: u32) -> BigUint {
        Pow::pow(self.clone(), exponent)
    }
}

impl Pow<&u32> for &BigUint {
    type Output = BigUint;
    fn pow(self, exponent: &u32) -> BigUint {
        Pow::pow(self.clone(), *exponent)
    }
}
