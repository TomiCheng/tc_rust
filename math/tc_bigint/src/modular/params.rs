//! Reusable Montgomery parameters for odd moduli.

#[cfg(feature = "alloc")]
use alloc::vec;

use super::mul::montgomery_inverse;
#[cfg(feature = "alloc")]
use crate::arithmetic::{div_rem, square};
use crate::arithmetic::{fixed_div_rem, fixed_mul_wide, fixed_wide_rem, fixed_wrapping_neg};
#[cfg(feature = "alloc")]
use crate::{BigUint, Limb};
use crate::{FixedBigUint, Odd, Word};

/// Precomputed Montgomery parameters for a dynamically sized odd modulus.
///
/// Constructing this value computes `R mod n` and `R² mod n` once. Clone and
/// reuse it when several operations share the same modulus.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MontyParams<T> {
    pub(super) modulus: Odd<T>,
    pub(super) mod_neg_inv: Word,
    pub(super) r: T,
    pub(super) r2: T,
}

#[cfg(feature = "alloc")]
impl MontyParams<BigUint> {
    /// Precomputes Montgomery constants for an odd `BigUint` modulus.
    ///
    /// ```
    /// use tc_bigint::{BigUint, Odd, modular::MontyParams};
    /// let params = MontyParams::new(Odd::new(BigUint::from(101_u8)).unwrap());
    /// assert_eq!(params.modulus(), &BigUint::from(101_u8));
    /// ```
    pub fn new(modulus: Odd<BigUint>) -> Self {
        let modulus_words = modulus.as_ref().as_limbs();
        let modulus_len = modulus_words.len();
        debug_assert!(modulus_len != 0);

        let mod_neg_inv = montgomery_inverse(modulus_words[0].0);
        let mut radix = vec![Limb(0); modulus_len + 1];
        radix[modulus_len] = Limb(1);
        let r = BigUint::from_limbs(div_rem(&radix, modulus_words).1);
        let r2 = BigUint::from_limbs(div_rem(&square(r.as_limbs()), modulus_words).1);

        Self {
            modulus,
            mod_neg_inv,
            r,
            r2,
        }
    }

    /// Returns the odd modulus.
    ///
    /// ```
    /// use tc_bigint::{BigUint, Odd, modular::MontyParams};
    /// let params = MontyParams::new(Odd::new(BigUint::from(101_u8)).unwrap());
    /// assert_eq!(params.modulus(), &BigUint::from(101_u8));
    /// ```
    pub fn modulus(&self) -> &BigUint {
        self.modulus.as_ref()
    }

    /// Returns Montgomery one, `R mod n`.
    ///
    /// ```
    /// use tc_bigint::{BigUint, Odd, modular::MontyParams};
    /// let params = MontyParams::new(Odd::new(BigUint::from(101_u8)).unwrap());
    /// assert!(params.one() < params.modulus());
    /// ```
    pub fn one(&self) -> &BigUint {
        &self.r
    }

    /// Returns `R² mod n`, used to enter Montgomery form.
    ///
    /// ```
    /// use tc_bigint::{BigUint, ModMul, Odd, modular::MontyParams};
    /// let params = MontyParams::new(Odd::new(BigUint::from(101_u8)).unwrap());
    /// assert_eq!(params.one().mod_mul(params.one(), params.modulus()), *params.r2());
    /// ```
    pub fn r2(&self) -> &BigUint {
        &self.r2
    }
}

/// Precomputed Montgomery parameters for a fixed-width odd modulus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedMontyParams<const N: usize> {
    pub(super) modulus: Odd<FixedBigUint<N>>,
    pub(super) mod_neg_inv: Word,
    pub(super) r: FixedBigUint<N>,
    pub(super) r2: FixedBigUint<N>,
}

impl<const N: usize> FixedMontyParams<N> {
    /// Precomputes Montgomery constants without allocating.
    ///
    /// ```
    /// use tc_bigint::{Odd, U128, modular::FixedMontyParams};
    /// let params = FixedMontyParams::new(Odd::new(U128::from(101_u8)).unwrap());
    /// assert_eq!(params.modulus(), &U128::from(101_u8));
    /// ```
    pub fn new(modulus: Odd<FixedBigUint<N>>) -> Self {
        let modulus_words = modulus.as_ref().as_limbs();
        let mod_neg_inv = montgomery_inverse(modulus_words[0].0);

        let radix_minus_modulus = fixed_wrapping_neg(modulus_words);
        let r = fixed_div_rem(&radix_minus_modulus, modulus_words).1;
        let (r2_low, r2_high) = fixed_mul_wide(&r, &r);
        let r2 = fixed_wide_rem(&r2_low, &r2_high, modulus_words);

        Self {
            modulus,
            mod_neg_inv,
            r: FixedBigUint::from_limbs(r),
            r2: FixedBigUint::from_limbs(r2),
        }
    }

    /// Returns the odd modulus.
    ///
    /// ```
    /// use tc_bigint::{Odd, U128, modular::FixedMontyParams};
    /// let params = FixedMontyParams::new(Odd::new(U128::from(101_u8)).unwrap());
    /// assert_eq!(params.modulus(), &U128::from(101_u8));
    /// ```
    pub fn modulus(&self) -> &FixedBigUint<N> {
        self.modulus.as_ref()
    }

    /// Returns Montgomery one, `R mod n`.
    ///
    /// ```
    /// use tc_bigint::{Odd, U128, modular::FixedMontyParams};
    /// let params = FixedMontyParams::new(Odd::new(U128::from(101_u8)).unwrap());
    /// assert!(params.one() < params.modulus());
    /// ```
    pub fn one(&self) -> &FixedBigUint<N> {
        &self.r
    }

    /// Returns `R² mod n`, used to enter Montgomery form.
    ///
    /// ```
    /// use tc_bigint::{ModMul, Odd, U128, modular::FixedMontyParams};
    /// let params = FixedMontyParams::new(Odd::new(U128::from(101_u8)).unwrap());
    /// assert_eq!(params.one().mod_mul(params.one(), params.modulus()), *params.r2());
    /// ```
    pub fn r2(&self) -> &FixedBigUint<N> {
        &self.r2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ModMul, U128, Word};

    #[test]
    fn fixed_parameters_compute_montgomery_one_and_r_squared() {
        let modulus = Odd::new(U128::from(101_u8)).unwrap();
        let params = FixedMontyParams::new(modulus);
        let radix = U128::from(2_u8).mod_pow(&U128::from(128_u16), &U128::from(101_u8));
        assert_eq!(*params.one(), radix);
        assert_eq!(
            params.one().mod_mul(params.one(), params.modulus()),
            *params.r2()
        );
        assert_eq!(params.modulus().as_limbs()[0].0 & 1, 1 as Word);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_parameters_match_modular_definition() {
        let dynamic = MontyParams::new(Odd::new(BigUint::from(101_u8)).unwrap());
        assert_eq!(dynamic.modulus(), &BigUint::from(101_u8));
        assert_eq!(
            dynamic.one(),
            &BigUint::from(2_u8).mod_pow(&BigUint::from(Word::BITS), &BigUint::from(101_u8),)
        );
        assert_eq!(
            dynamic.r2(),
            &dynamic.one().mod_mul(dynamic.one(), dynamic.modulus())
        );
    }
}
