use alloc::vec;
use alloc::vec::Vec;
use core::ops::Add;

use crate::error::BinPolyError;
use crate::invert::{BinPolyInv, ItohTsujii};
use crate::multiplier::{BinPolyMul, BinPolyMultiplier};

/// Owned binary-polynomial value bound to a reduction polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryPoly {
    multiplier: BinPolyMultiplier,
    limbs: Vec<u64>,
}

impl BinaryPoly {
    /// Constructs zero in the configured quotient ring or field.
    pub fn zero(multiplier: BinPolyMultiplier) -> Self {
        let limbs = vec![0_u64; multiplier.size()];
        Self { multiplier, limbs }
    }

    /// Constructs one in the configured quotient ring or field.
    pub fn one(multiplier: BinPolyMultiplier) -> Self {
        let mut value = Self::zero(multiplier);
        value.limbs[0] = 1;
        value
    }

    /// Constructs a reduced value from little-endian limbs.
    pub fn from_limbs(
        multiplier: BinPolyMultiplier,
        limbs: Vec<u64>,
    ) -> Result<Self, BinPolyError> {
        if limbs.len() != multiplier.size() {
            return Err(BinPolyError::InvalidLength {
                expected: multiplier.size(),
                actual: limbs.len(),
            });
        }
        if multiplier.n() & 63 != 0 && limbs[limbs.len() - 1] >> (multiplier.n() & 63) != 0 {
            return Err(BinPolyError::UnreducedValue);
        }
        Ok(Self { multiplier, limbs })
    }

    /// Returns the field/ring multiplier attached to this value.
    pub const fn multiplier(&self) -> &BinPolyMultiplier {
        &self.multiplier
    }

    /// Returns the little-endian limbs.
    pub fn as_limbs(&self) -> &[u64] {
        &self.limbs
    }

    /// Consumes this value and returns its limbs.
    pub fn into_limbs(self) -> Vec<u64> {
        self.limbs
    }

    /// Multiplies two values using their shared modulus.
    pub fn multiply(&self, rhs: &Self) -> Result<Self, BinPolyError> {
        self.ensure_same_modulus(rhs)?;
        let mut limbs = vec![0_u64; self.limbs.len()];
        self.multiplier
            .multiply(&self.limbs, &rhs.limbs, &mut limbs);
        Ok(Self {
            multiplier: self.multiplier.clone(),
            limbs,
        })
    }

    /// Squares this value.
    pub fn square(&self) -> Self {
        let mut limbs = vec![0_u64; self.limbs.len()];
        self.multiplier.square(&self.limbs, &mut limbs);
        Self {
            multiplier: self.multiplier.clone(),
            limbs,
        }
    }

    /// Applies `count` repeated squarings. A count of zero returns a clone.
    pub fn square_pow(&self, count: usize) -> Self {
        if count == 0 {
            return self.clone();
        }
        let mut limbs = vec![0_u64; self.limbs.len()];
        self.multiplier.square_n(&self.limbs, count, &mut limbs);
        Self {
            multiplier: self.multiplier.clone(),
            limbs,
        }
    }

    /// Computes the Itoh-Tsujii inverse.
    ///
    /// The caller attests that a trinomial or pentanomial modulus is
    /// irreducible. Zero maps to zero, matching the underlying BC routine.
    pub fn invert(&self) -> Result<Self, BinPolyError> {
        let inverter = ItohTsujii::new(self.multiplier.clone())?;
        let mut limbs = vec![0_u64; self.limbs.len()];
        inverter.invert(&self.limbs, &mut limbs);
        Ok(Self {
            multiplier: self.multiplier.clone(),
            limbs,
        })
    }

    fn ensure_same_modulus(&self, rhs: &Self) -> Result<(), BinPolyError> {
        if self.multiplier != rhs.multiplier {
            return Err(BinPolyError::MismatchedModulus);
        }
        Ok(())
    }
}

#[allow(clippy::suspicious_arithmetic_impl)] // Addition in GF(2) is coefficient-wise XOR.
impl Add for &BinaryPoly {
    type Output = BinaryPoly;

    fn add(self, rhs: Self) -> Self::Output {
        self.ensure_same_modulus(rhs)
            .expect("cannot add binary polynomials with different moduli");
        let limbs = self
            .limbs
            .iter()
            .zip(&rhs.limbs)
            .map(|(&x, &y)| x ^ y)
            .collect();
        BinaryPoly {
            multiplier: self.multiplier.clone(),
            limbs,
        }
    }
}

#[allow(clippy::suspicious_arithmetic_impl)] // Addition in GF(2) is coefficient-wise XOR.
impl Add<&BinaryPoly> for BinaryPoly {
    type Output = BinaryPoly;

    fn add(mut self, rhs: &BinaryPoly) -> Self::Output {
        self.ensure_same_modulus(rhs)
            .expect("cannot add binary polynomials with different moduli");
        for (x, &y) in self.limbs.iter_mut().zip(&rhs.limbs) {
            *x ^= y;
        }
        self
    }
}

impl Add<BinaryPoly> for BinaryPoly {
    type Output = BinaryPoly;

    fn add(self, rhs: BinaryPoly) -> Self::Output {
        self + &rhs
    }
}

impl Add<BinaryPoly> for &BinaryPoly {
    type Output = BinaryPoly;

    fn add(self, rhs: BinaryPoly) -> Self::Output {
        rhs + self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_facade_composes_arithmetic() {
        let multiplier = BinPolyMultiplier::trinomial(113, 9).unwrap();
        let one = BinaryPoly::one(multiplier.clone());
        let x = BinaryPoly::from_limbs(multiplier, vec![7, 9]).unwrap();
        assert_eq!(x.multiply(&one).unwrap(), x);
        assert_eq!(&x + &x, BinaryPoly::zero(x.multiplier.clone()));
        assert_eq!(x.square_pow(1), x.square());
        assert_eq!(x.multiply(&x.invert().unwrap()).unwrap(), one);
    }

    #[test]
    fn rejects_unreduced_input() {
        let multiplier = BinPolyMultiplier::trinomial(65, 7).unwrap();
        let error = BinaryPoly::from_limbs(multiplier, vec![0, 2]).unwrap_err();
        assert_eq!(error, BinPolyError::UnreducedValue);
    }
}
