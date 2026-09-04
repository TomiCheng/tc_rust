//! Exponentiation for [`FixedBigInt`].

use crate::traits::{ModPow, One, Pow, Signed};
use crate::{FixedBigInt, arithmetic};

impl<const N: usize> FixedBigInt<N> {
    /// Returns `self^exponent mod modulus`.
    ///
    /// Negative exponents use a modular inverse. The modulus must be positive.
    pub fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        assert!(modulus.is_positive(), "modulus must be positive");
        let base = self.rem_euclid(modulus);
        let result = arithmetic::fixed_mod_pow(&base.limbs, &exponent.magnitude(), &modulus.limbs);
        let result = Self::from_sign_magnitude(false, result)
            .expect("a modular result is smaller than the positive modulus");
        if exponent.is_negative() {
            result
                .mod_inverse(modulus)
                .expect("base is not invertible for a negative exponent")
        } else {
            result
        }
    }
}

impl<const N: usize> Pow<u32> for FixedBigInt<N> {
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

impl<const N: usize> Pow<&u32> for FixedBigInt<N> {
    type Output = Self;
    fn pow(self, exponent: &u32) -> Self {
        Pow::pow(self, *exponent)
    }
}

impl<const N: usize> Pow<u32> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;
    fn pow(self, exponent: u32) -> Self::Output {
        Pow::pow(*self, exponent)
    }
}

impl<const N: usize> Pow<&u32> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;
    fn pow(self, exponent: &u32) -> Self::Output {
        Pow::pow(*self, *exponent)
    }
}

impl<const N: usize> ModPow for FixedBigInt<N> {
    type Output = Self;
    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        FixedBigInt::mod_pow(self, exponent, modulus)
    }
}
