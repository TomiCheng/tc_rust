//! Implementations of the crate's modular operation traits.
//!
//! The integer types keep their inherent modular methods, which need access to
//! their own representation; these impls forward to them so that every `Mod*`
//! trait is implemented in one place.

use crate::{FixedBigInt, FixedBigUint, ModAdd, ModInverse, ModMul, ModPow, ModSub};

use super::mul::{fixed_add_mod, fixed_sub_mod};
#[cfg(feature = "alloc")]
use crate::{BigInt, BigUint};

#[cfg(feature = "alloc")]
impl ModAdd for BigUint {
    type Output = Self;

    fn mod_add(&self, rhs: &Self, modulus: &Self) -> Self {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        let lhs = self % modulus;
        let rhs = rhs % modulus;
        let distance = modulus - &rhs;
        if lhs >= distance {
            lhs - distance
        } else {
            lhs + rhs
        }
    }
}

#[cfg(feature = "alloc")]
impl ModSub for BigUint {
    type Output = Self;

    fn mod_sub(&self, rhs: &Self, modulus: &Self) -> Self {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        let lhs = self % modulus;
        let rhs = rhs % modulus;
        if lhs >= rhs {
            lhs - rhs
        } else {
            modulus - (rhs - lhs)
        }
    }
}

#[cfg(feature = "alloc")]
impl ModMul for BigUint {
    type Output = Self;

    fn mod_mul(&self, rhs: &Self, modulus: &Self) -> Self {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        ((self % modulus) * (rhs % modulus)) % modulus
    }
}

#[cfg(feature = "alloc")]
impl ModAdd for BigInt {
    type Output = Self;

    fn mod_add(&self, rhs: &Self, modulus: &Self) -> Self {
        assert!(modulus.sign() > 0, "modulus must be positive");
        let lhs = self.rem_euclid(modulus);
        let rhs = rhs.rem_euclid(modulus);
        let distance = modulus - &rhs;
        if lhs >= distance {
            lhs - distance
        } else {
            lhs + rhs
        }
    }
}

#[cfg(feature = "alloc")]
impl ModSub for BigInt {
    type Output = Self;

    fn mod_sub(&self, rhs: &Self, modulus: &Self) -> Self {
        assert!(modulus.sign() > 0, "modulus must be positive");
        let lhs = self.rem_euclid(modulus);
        let rhs = rhs.rem_euclid(modulus);
        if lhs >= rhs {
            lhs - rhs
        } else {
            modulus - (rhs - lhs)
        }
    }
}

#[cfg(feature = "alloc")]
impl ModMul for BigInt {
    type Output = Self;

    fn mod_mul(&self, rhs: &Self, modulus: &Self) -> Self {
        assert!(modulus.sign() > 0, "modulus must be positive");
        let lhs = BigUint::try_from(self.rem_euclid(modulus))
            .expect("Euclidean remainder is non-negative");
        let rhs = BigUint::try_from(rhs.rem_euclid(modulus))
            .expect("Euclidean remainder is non-negative");
        let modulus = BigUint::try_from(modulus.clone()).expect("modulus is positive");
        BigInt::from(lhs.mod_mul(&rhs, &modulus))
    }
}

impl<const N: usize> ModAdd for FixedBigUint<N> {
    type Output = Self;

    fn mod_add(&self, rhs: &Self, modulus: &Self) -> Self {
        assert!(
            !crate::LimbArray::new(*(modulus.as_limbs())).is_zero(),
            "modulus must be non-zero"
        );
        let lhs = {
            let (low, high) = crate::LimbArray::new(*(self.as_limbs()))
                .div_rem(&crate::LimbArray::new(*(modulus.as_limbs())));
            (low.into_limbs(), high.into_limbs())
        }
        .1;
        let rhs = {
            let (low, high) = crate::LimbArray::new(*(rhs.as_limbs()))
                .div_rem(&crate::LimbArray::new(*(modulus.as_limbs())));
            (low.into_limbs(), high.into_limbs())
        }
        .1;
        Self::from_limbs(fixed_add_mod(&lhs, &rhs, modulus.as_limbs()))
    }
}

impl<const N: usize> ModSub for FixedBigUint<N> {
    type Output = Self;

    fn mod_sub(&self, rhs: &Self, modulus: &Self) -> Self {
        assert!(
            !crate::LimbArray::new(*(modulus.as_limbs())).is_zero(),
            "modulus must be non-zero"
        );
        let lhs = {
            let (low, high) = crate::LimbArray::new(*(self.as_limbs()))
                .div_rem(&crate::LimbArray::new(*(modulus.as_limbs())));
            (low.into_limbs(), high.into_limbs())
        }
        .1;
        let rhs = {
            let (low, high) = crate::LimbArray::new(*(rhs.as_limbs()))
                .div_rem(&crate::LimbArray::new(*(modulus.as_limbs())));
            (low.into_limbs(), high.into_limbs())
        }
        .1;
        Self::from_limbs(fixed_sub_mod(&lhs, &rhs, modulus.as_limbs()))
    }
}

impl<const N: usize> ModMul for FixedBigUint<N> {
    type Output = Self;

    fn mod_mul(&self, rhs: &Self, modulus: &Self) -> Self {
        assert!(
            !crate::LimbArray::new(*(modulus.as_limbs())).is_zero(),
            "modulus must be non-zero"
        );
        let (low, high) = {
            let (low, high) = crate::LimbArray::new(*(self.as_limbs()))
                .mul_wide(&crate::LimbArray::new(*(rhs.as_limbs())));
            (low.into_limbs(), high.into_limbs())
        };
        Self::from_limbs(
            crate::LimbArray::new(low)
                .wide_rem(
                    &crate::LimbArray::new(high),
                    &crate::LimbArray::new(*(modulus.as_limbs())),
                )
                .into_limbs(),
        )
    }
}

impl<const N: usize> ModAdd for FixedBigInt<N> {
    type Output = Self;

    fn mod_add(&self, rhs: &Self, modulus: &Self) -> Self {
        assert!(modulus.sign() > 0, "modulus must be positive");
        let lhs = self.rem_euclid(modulus);
        let rhs = rhs.rem_euclid(modulus);
        Self::from_limbs(fixed_add_mod(
            lhs.as_limbs(),
            rhs.as_limbs(),
            modulus.as_limbs(),
        ))
    }
}

impl<const N: usize> ModSub for FixedBigInt<N> {
    type Output = Self;

    fn mod_sub(&self, rhs: &Self, modulus: &Self) -> Self {
        assert!(modulus.sign() > 0, "modulus must be positive");
        let lhs = self.rem_euclid(modulus);
        let rhs = rhs.rem_euclid(modulus);
        Self::from_limbs(fixed_sub_mod(
            lhs.as_limbs(),
            rhs.as_limbs(),
            modulus.as_limbs(),
        ))
    }
}

impl<const N: usize> ModMul for FixedBigInt<N> {
    type Output = Self;

    fn mod_mul(&self, rhs: &Self, modulus: &Self) -> Self {
        assert!(modulus.sign() > 0, "modulus must be positive");
        let lhs = self.rem_euclid(modulus);
        let rhs = rhs.rem_euclid(modulus);
        let unsigned_modulus = FixedBigUint::from_limbs(*modulus.as_limbs());
        let result = FixedBigUint::from_limbs(*lhs.as_limbs()).mod_mul(
            &FixedBigUint::from_limbs(*rhs.as_limbs()),
            &unsigned_modulus,
        );
        Self::from_limbs(*result.as_limbs())
    }
}

#[cfg(feature = "alloc")]
impl ModPow for BigUint {
    type Output = Self;

    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        BigUint::mod_pow(self, exponent, modulus)
    }
}

#[cfg(feature = "alloc")]
impl ModPow for BigInt {
    type Output = Self;
    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        BigInt::mod_pow(self, exponent, modulus)
    }
}

impl<const N: usize> ModPow for FixedBigUint<N> {
    type Output = Self;
    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        FixedBigUint::mod_pow(self, exponent, modulus)
    }
}

impl<const N: usize> ModPow for FixedBigInt<N> {
    type Output = Self;
    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        FixedBigInt::mod_pow(self, exponent, modulus)
    }
}

#[cfg(feature = "alloc")]
impl ModInverse for BigUint {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        BigUint::mod_inverse(self, modulus)
    }
}

#[cfg(feature = "alloc")]
impl ModInverse for BigInt {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        BigInt::mod_inverse(self, modulus)
    }
}

impl<const N: usize> ModInverse for FixedBigUint<N> {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        FixedBigUint::mod_inverse(self, modulus)
    }
}

impl<const N: usize> ModInverse for FixedBigInt<N> {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        FixedBigInt::mod_inverse(self, modulus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{I128, U128};

    #[test]
    fn fixed_unsigned_modular_operations_do_not_overflow() {
        let modulus = U128::from(101_u8);
        let max = U128::MAX;
        assert_eq!(max.mod_add(&max, &modulus), U128::from(57_u8));
        assert_eq!(
            U128::from(3_u8).mod_sub(&U128::from(5_u8), &modulus),
            U128::from(99_u8)
        );

        let result = max.mod_mul(&max, &modulus);
        #[cfg(feature = "alloc")]
        assert_eq!(
            BigUint::from(result),
            BigUint::from(max).mod_mul(&BigUint::from(max), &BigUint::from(101_u8))
        );
        #[cfg(not(feature = "alloc"))]
        assert_eq!(result, U128::from(80_u8));
    }

    #[test]
    fn fixed_signed_modular_operations_return_non_negative_residues() {
        let modulus = I128::from(101_u8);
        let left = I128::from(-7_i8);
        let right = I128::from(9_i8);
        assert_eq!(left.mod_add(&right, &modulus), I128::from(2_u8));
        assert_eq!(left.mod_sub(&right, &modulus), I128::from(85_u8));
        assert_eq!(left.mod_mul(&right, &modulus), I128::from(38_u8));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_modular_operations_match_fixed_results() {
        let modulus = BigUint::from(101_u8);
        let left = BigUint::from(u128::MAX);
        assert_eq!(left.mod_mul(&left, &modulus), BigUint::from(80_u8));

        let modulus = BigInt::from(101_u8);
        let left = BigInt::from(-7_i8);
        let right = BigInt::from(9_i8);
        assert_eq!(left.mod_add(&right, &modulus), BigInt::from(2_u8));
        assert_eq!(left.mod_sub(&right, &modulus), BigInt::from(85_u8));
        assert_eq!(left.mod_mul(&right, &modulus), BigInt::from(38_u8));
    }
}
