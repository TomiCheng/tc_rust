use core::ops::Add;

use crate::error::BinPolyError;
use crate::multiplier::BinPolyMultiplier;
use crate::ops::clear;

/// Allocation-free binary polynomial with exactly `N` little-endian limbs.
///
/// The attached modulus must have `size(n) == N`. Multiplication and squaring
/// use two `N`-limb rows as stack scratch, avoiding unstable `[u64; 2 * N]`
/// generic-const expressions. Reducers still receive ordinary `u64` slices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedBinaryPoly<const N: usize> {
    multiplier: BinPolyMultiplier,
    limbs: [u64; N],
}

impl<const N: usize> FixedBinaryPoly<N> {
    /// Constructs zero for `multiplier`.
    pub fn zero(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
        check_width::<N>(&multiplier)?;
        Ok(Self {
            multiplier,
            limbs: [0; N],
        })
    }

    /// Constructs one for `multiplier`.
    pub fn one(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
        let mut value = Self::zero(multiplier)?;
        if N != 0 {
            value.limbs[0] = 1;
        }
        Ok(value)
    }

    /// Constructs a reduced value from exactly `N` little-endian limbs.
    pub fn from_limbs(
        multiplier: BinPolyMultiplier,
        limbs: [u64; N],
    ) -> Result<Self, BinPolyError> {
        check_width::<N>(&multiplier)?;
        if multiplier.n() & 63 != 0 && limbs[N - 1] >> (multiplier.n() & 63) != 0 {
            return Err(BinPolyError::UnreducedValue);
        }
        Ok(Self { multiplier, limbs })
    }

    /// Returns the attached field/ring multiplier.
    pub const fn multiplier(&self) -> &BinPolyMultiplier {
        &self.multiplier
    }

    /// Returns the little-endian limbs.
    pub const fn as_limbs(&self) -> &[u64; N] {
        &self.limbs
    }

    /// Consumes this value and returns the limb array.
    pub fn into_limbs(self) -> [u64; N] {
        self.limbs
    }

    /// Multiplies two values without allocation.
    pub fn multiply(&self, rhs: &Self) -> Result<Self, BinPolyError> {
        self.ensure_same_modulus(rhs)?;
        let mut limbs = [0_u64; N];
        self.multiplier
            .multiply_fixed(&self.limbs, &rhs.limbs, &mut limbs);
        Ok(Self {
            multiplier: self.multiplier.clone(),
            limbs,
        })
    }

    /// Squares this value without allocation.
    pub fn square(&self) -> Self {
        let mut limbs = [0_u64; N];
        self.multiplier.square_fixed(&self.limbs, &mut limbs);
        Self {
            multiplier: self.multiplier.clone(),
            limbs,
        }
    }

    /// Applies `count` repeated squarings without allocation.
    pub fn square_pow(&self, count: usize) -> Self {
        if count == 0 {
            return self.clone();
        }
        let mut output = [0_u64; N];
        self.multiplier
            .square_n_fixed(&self.limbs, count, &mut output);
        Self {
            multiplier: self.multiplier.clone(),
            limbs: output,
        }
    }

    /// Computes an allocation-free Itoh-Tsujii inverse.
    ///
    /// The trinomial or pentanomial modulus must be irreducible. Zero maps to
    /// zero. Binomial moduli are rejected because they do not define a field.
    pub fn invert(&self) -> Result<Self, BinPolyError> {
        if self.multiplier.is_binomial() {
            return Err(BinPolyError::BinomialInversion);
        }

        let mut b = WipeArray(self.limbs);
        let mut t = WipeArray([0_u64; N]);
        let mut next = WipeArray([0_u64; N]);
        let e = self.multiplier.n() - 1;
        let mut j = 1_usize;
        let bit_length = usize::BITS as usize - e.leading_zeros() as usize;

        for i in (0..bit_length.saturating_sub(1)).rev() {
            square_n_fixed(&self.multiplier, b.as_ref(), j, t.as_mut());
            self.multiplier
                .multiply_fixed(b.as_ref(), t.as_ref(), next.as_mut());
            core::mem::swap(&mut b, &mut next);
            j <<= 1;

            if e & (1_usize << i) != 0 {
                self.multiplier.square_fixed(b.as_ref(), t.as_mut());
                self.multiplier
                    .multiply_fixed(t.as_ref(), &self.limbs, next.as_mut());
                core::mem::swap(&mut b, &mut next);
                j += 1;
            }
        }
        debug_assert_eq!(j, e);

        let mut limbs = [0_u64; N];
        self.multiplier.square_fixed(b.as_ref(), &mut limbs);
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
impl<const N: usize> Add for &FixedBinaryPoly<N> {
    type Output = FixedBinaryPoly<N>;

    fn add(self, rhs: Self) -> Self::Output {
        self.ensure_same_modulus(rhs)
            .expect("cannot add binary polynomials with different moduli");
        let mut limbs = [0_u64; N];
        for (output, (&x, &y)) in limbs.iter_mut().zip(self.limbs.iter().zip(&rhs.limbs)) {
            *output = x ^ y;
        }
        FixedBinaryPoly {
            multiplier: self.multiplier.clone(),
            limbs,
        }
    }
}

#[allow(clippy::suspicious_arithmetic_impl)] // Addition in GF(2) is coefficient-wise XOR.
impl<const N: usize> Add<&FixedBinaryPoly<N>> for FixedBinaryPoly<N> {
    type Output = FixedBinaryPoly<N>;

    fn add(mut self, rhs: &FixedBinaryPoly<N>) -> Self::Output {
        self.ensure_same_modulus(rhs)
            .expect("cannot add binary polynomials with different moduli");
        for (x, &y) in self.limbs.iter_mut().zip(&rhs.limbs) {
            *x ^= y;
        }
        self
    }
}

impl<const N: usize> Add<FixedBinaryPoly<N>> for FixedBinaryPoly<N> {
    type Output = FixedBinaryPoly<N>;

    fn add(self, rhs: FixedBinaryPoly<N>) -> Self::Output {
        self + &rhs
    }
}

impl<const N: usize> Add<FixedBinaryPoly<N>> for &FixedBinaryPoly<N> {
    type Output = FixedBinaryPoly<N>;

    fn add(self, rhs: FixedBinaryPoly<N>) -> Self::Output {
        rhs + self
    }
}

fn check_width<const N: usize>(multiplier: &BinPolyMultiplier) -> Result<(), BinPolyError> {
    if N != multiplier.size() {
        return Err(BinPolyError::InvalidLength {
            expected: multiplier.size(),
            actual: N,
        });
    }
    Ok(())
}

fn square_n_fixed<const N: usize>(
    multiplier: &BinPolyMultiplier,
    x: &[u64; N],
    count: usize,
    z: &mut [u64; N],
) {
    debug_assert!(count > 0);
    multiplier.square_n_fixed(x, count, z);
}

struct WipeArray<const N: usize>([u64; N]);

impl<const N: usize> WipeArray<N> {
    fn as_ref(&self) -> &[u64; N] {
        &self.0
    }

    fn as_mut(&mut self) -> &mut [u64; N] {
        &mut self.0
    }
}

impl<const N: usize> Drop for WipeArray<N> {
    fn drop(&mut self) {
        clear(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;

    use super::*;

    #[test]
    #[cfg(feature = "alloc")]
    fn fixed_inverse_matches_allocating_facade() {
        let multiplier = BinPolyMultiplier::trinomial(113, 9).unwrap();
        let fixed =
            FixedBinaryPoly::<2>::from_limbs(multiplier.clone(), [0x0123_4567_89AB_CDEF, 0x1234])
                .unwrap();
        let dynamic =
            crate::BinaryPoly::from_limbs(multiplier, fixed.as_limbs().as_slice().to_vec())
                .unwrap();

        assert_eq!(
            fixed.invert().unwrap().as_limbs().as_slice(),
            dynamic.invert().unwrap().as_limbs()
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn fixed_square_matches_allocating_facade_across_moduli() {
        let mut seed = 0xF17E_D5A4_2C39_81B7_u64;
        check_fixed_squares::<2>(BinPolyMultiplier::trinomial(113, 9).unwrap(), &mut seed);
        check_fixed_squares::<4>(BinPolyMultiplier::trinomial(193, 15).unwrap(), &mut seed);
        check_fixed_squares::<4>(BinPolyMultiplier::trinomial(233, 74).unwrap(), &mut seed);
        check_fixed_squares::<4>(BinPolyMultiplier::trinomial(239, 158).unwrap(), &mut seed);
        check_fixed_squares::<7>(BinPolyMultiplier::trinomial(409, 87).unwrap(), &mut seed);
        check_fixed_squares::<3>(
            BinPolyMultiplier::pentanomial(131, 2, 3, 8).unwrap(),
            &mut seed,
        );
        check_fixed_squares::<3>(
            BinPolyMultiplier::pentanomial(163, 3, 6, 7).unwrap(),
            &mut seed,
        );
        check_fixed_squares::<5>(
            BinPolyMultiplier::pentanomial(283, 5, 7, 12).unwrap(),
            &mut seed,
        );
        check_fixed_squares::<9>(
            BinPolyMultiplier::pentanomial(571, 2, 5, 10).unwrap(),
            &mut seed,
        );
        check_fixed_squares::<1>(BinPolyMultiplier::binomial(64).unwrap(), &mut seed);
        check_fixed_squares::<2>(BinPolyMultiplier::binomial(127).unwrap(), &mut seed);
    }

    #[cfg(feature = "alloc")]
    fn check_fixed_squares<const N: usize>(multiplier: BinPolyMultiplier, seed: &mut u64) {
        for _ in 0..4 {
            let mut limbs = [0_u64; N];
            for word in &mut limbs {
                *word = next(seed);
            }
            if multiplier.n() & 63 != 0 {
                limbs[N - 1] &= (1_u64 << (multiplier.n() & 63)) - 1;
            }

            let fixed = FixedBinaryPoly::from_limbs(multiplier.clone(), limbs).unwrap();
            let dynamic =
                crate::BinaryPoly::from_limbs(multiplier.clone(), Vec::from(limbs)).unwrap();
            assert_eq!(
                fixed.square().as_limbs().as_slice(),
                dynamic.square().as_limbs(),
                "n={}",
                multiplier.n()
            );
            assert_eq!(
                fixed.square_pow(7).as_limbs().as_slice(),
                dynamic.square_pow(7).as_limbs(),
                "square_pow n={}",
                multiplier.n()
            );
        }
    }

    #[cfg(feature = "alloc")]
    fn next(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    #[test]
    fn fixed_value_composes_arithmetic() {
        let multiplier = BinPolyMultiplier::pentanomial(163, 3, 6, 7).unwrap();
        let x = FixedBinaryPoly::<3>::from_limbs(multiplier.clone(), [7, 9, 11]).unwrap();
        let one = FixedBinaryPoly::<3>::one(multiplier).unwrap();
        assert_eq!(x.multiply(&one).unwrap(), x);
        assert_eq!(
            &x + &x,
            FixedBinaryPoly::zero(x.multiplier.clone()).unwrap()
        );
        assert_eq!(x.multiply(&x.invert().unwrap()).unwrap(), one);
    }

    #[test]
    fn fixed_width_must_match_modulus() {
        let multiplier = BinPolyMultiplier::trinomial(113, 9).unwrap();
        assert!(matches!(
            FixedBinaryPoly::<3>::zero(multiplier),
            Err(BinPolyError::InvalidLength {
                expected: 2,
                actual: 3
            })
        ));
    }
}
