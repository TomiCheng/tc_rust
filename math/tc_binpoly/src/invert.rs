use alloc::vec;

use crate::error::BinPolyError;
use crate::multiplier::{BinPolyMul, BinPolyMultiplier};
use crate::ops::clear;
#[cfg(debug_assertions)]
use crate::ops::{equal_to_one, equal_to_zero};

/// Multiplicative inversion for a fixed binary extension field.
pub trait BinPolyInv {
    /// Polynomial bit length.
    fn n(&self) -> usize;

    /// Number of limbs in a reduced value.
    fn size(&self) -> usize;

    /// Computes `z = x^-1`; by convention zero maps to zero.
    fn invert(&self, x: &[u64], z: &mut [u64]);
}

/// Itoh-Tsujii inversion driven by a statically dispatched multiplier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItohTsujii {
    multiplier: BinPolyMultiplier,
}

impl ItohTsujii {
    /// Creates an inverter for an irreducible trinomial or pentanomial.
    ///
    /// Irreducibility is the caller's attestation. Binomial moduli are rejected
    /// because `x^n + 1` always has `x = 1` as a root over `GF(2)`.
    pub fn new(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
        if multiplier.is_binomial() {
            return Err(BinPolyError::BinomialInversion);
        }
        Ok(Self { multiplier })
    }

    /// Returns the multiplier used by this inverter.
    pub const fn multiplier(&self) -> &BinPolyMultiplier {
        &self.multiplier
    }
}

impl BinPolyInv for ItohTsujii {
    fn n(&self) -> usize {
        self.multiplier.n()
    }

    fn size(&self) -> usize {
        self.multiplier.size()
    }

    fn invert(&self, x: &[u64], z: &mut [u64]) {
        let n = self.n();
        let words = self.size();
        assert_eq!(x.len(), words, "invalid polynomial input length");
        assert_eq!(z.len(), words, "invalid polynomial output length");

        let mut b = x.to_vec();
        let mut t = vec![0_u64; words];
        let mut next = vec![0_u64; words];

        // b accumulates a_j = a^(2^j - 1). Walk e = n - 1 from the
        // bit below its MSB down to zero using double and increment steps.
        let e = n - 1;
        let mut j = 1_usize;
        let bit_length = usize::BITS as usize - e.leading_zeros() as usize;
        for i in (0..bit_length.saturating_sub(1)).rev() {
            self.multiplier.square_n(&b, j, &mut t);
            self.multiplier.multiply(&b, &t, &mut next);
            core::mem::swap(&mut b, &mut next);
            j <<= 1;

            if e & (1_usize << i) != 0 {
                self.multiplier.square(&b, &mut t);
                self.multiplier.multiply(&t, x, &mut next);
                core::mem::swap(&mut b, &mut next);
                j += 1;
            }
        }
        debug_assert_eq!(j, e);

        self.multiplier.square(&b, z);

        #[cfg(debug_assertions)]
        {
            let mut product = vec![0_u64; words];
            self.multiplier.multiply(z, x, &mut product);
            let ok = if equal_to_zero(x) != 0 {
                equal_to_zero(&product) != 0
            } else {
                equal_to_one(&product) != 0
            };
            debug_assert!(ok, "Itoh-Tsujii inverse self-check failed");
            clear(&mut product);
        }

        clear(&mut b);
        clear(&mut t);
        clear(&mut next);
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn rejects_binomial_ring() {
        let multiplier = BinPolyMultiplier::binomial(64).unwrap();
        assert_eq!(
            ItohTsujii::new(multiplier),
            Err(BinPolyError::BinomialInversion)
        );
    }

    #[test]
    fn inverse_round_trip_for_sect_fields() {
        for multiplier in [
            BinPolyMultiplier::trinomial(113, 9).unwrap(),
            BinPolyMultiplier::pentanomial(163, 3, 6, 7).unwrap(),
        ] {
            let inverter = ItohTsujii::new(multiplier.clone()).unwrap();
            let mut x = vec![0_u64; multiplier.size()];
            x[0] = 0x0123_4567_89AB_CDEF;
            x[1] = 0x0001_2345_6789_ABCD;
            let mut inverse = vec![0_u64; multiplier.size()];
            inverter.invert(&x, &mut inverse);
            let mut product = vec![0_u64; multiplier.size()];
            multiplier.multiply(&x, &inverse, &mut product);
            assert_eq!(equal_to_one(&product), u64::MAX);
        }
    }

    #[test]
    fn zero_and_one_are_fixed_points() {
        let multiplier = BinPolyMultiplier::trinomial(113, 9).unwrap();
        let inverter = ItohTsujii::new(multiplier.clone()).unwrap();
        let zero = vec![0_u64; multiplier.size()];
        let mut output = vec![9_u64; multiplier.size()];
        inverter.invert(&zero, &mut output);
        assert_eq!(output, zero);

        let mut one = zero;
        one[0] = 1;
        inverter.invert(&one, &mut output);
        assert_eq!(output, one);
    }
}
