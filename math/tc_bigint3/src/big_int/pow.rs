//! Exponentiation for [`BigInt`].

use crate::traits::{ModPow, One, Pow, Signed};
use crate::{BigInt, BigUint};

impl BigInt {
    /// Returns `self^exponent mod modulus`.
    ///
    /// A negative exponent uses the modular inverse of the positive-power
    /// result. The modulus must be positive.
    pub fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        assert!(modulus.is_positive(), "modulus must be positive");
        let (negative_exponent, exponent_magnitude) = exponent.sign_magnitude();
        let exponent = BigUint::from_limbs(exponent_magnitude);
        let base = self.rem_euclid(modulus);
        let base = BigUint::from_limbs(base.as_limbs().to_vec());
        let unsigned_modulus = BigUint::from_limbs(modulus.as_limbs().to_vec());
        let result = base.mod_pow(&exponent, &unsigned_modulus);
        let result = Self::from_sign_magnitude(false, result.as_limbs().to_vec());

        if negative_exponent {
            result
                .mod_inverse(modulus)
                .expect("base is not invertible for a negative exponent")
        } else {
            result
        }
    }
}

impl Pow<u32> for BigInt {
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

impl Pow<&u32> for BigInt {
    type Output = Self;
    fn pow(self, exponent: &u32) -> Self {
        Pow::pow(self, *exponent)
    }
}

impl Pow<u32> for &BigInt {
    type Output = BigInt;
    fn pow(self, exponent: u32) -> BigInt {
        Pow::pow(self.clone(), exponent)
    }
}

impl Pow<&u32> for &BigInt {
    type Output = BigInt;
    fn pow(self, exponent: &u32) -> BigInt {
        Pow::pow(self.clone(), *exponent)
    }
}

impl ModPow for BigInt {
    type Output = Self;
    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        BigInt::mod_pow(self, exponent, modulus)
    }
}
