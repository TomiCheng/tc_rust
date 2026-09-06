//! Caller-owned fixed-base comb tables for public scalars.
use crate::{AlgorithmError, Curve, Point};
use alloc::vec::Vec;

/// A fixed-base comb table. Table lookup is variable time.
#[derive(Clone)]
pub struct FixedPointTable<P> {
    points: Vec<P>,
    bits: usize,
    spacing: usize,
    width: usize,
}

impl<P: Point> FixedPointTable<P> {
    /// Precomputes a comb for scalars of at most `bits` bits.
    /// Width must be in `2..=8`; capacity must be nonzero.
    pub fn new(point: &P, bits: usize, width: usize) -> Self {
        assert!(bits > 0 && (2..=8).contains(&width));
        let spacing = bits.div_ceil(width);
        let mut powers = Vec::with_capacity(width);
        powers.push(point.clone());
        for i in 1..width {
            powers.push(powers[i - 1].times_pow2(spacing));
        }
        let mut points = Vec::with_capacity(1 << width);
        points.push(point.identity());
        for index in 1_usize..1 << width {
            let bit = index.trailing_zeros() as usize;
            points.push(points[index & (index - 1)].add(&powers[bit]));
        }
        Self {
            points,
            bits,
            spacing,
            width,
        }
    }

    /// Computes the fixed-base multiple. Public scalars only; rejects truncation.
    pub fn multiply(&self, scalar: &<P::Curve as Curve>::Scalar) -> Result<P, AlgorithmError> {
        if P::Curve::scalar_bit_length(scalar) > self.bits {
            return Err(AlgorithmError::ScalarTooLarge);
        }
        let mut result = self.points[0].clone();
        for row in (0..self.spacing).rev() {
            let mut index = 0;
            for column in 0..self.width {
                let bit = row + column * self.spacing;
                if bit < self.bits && P::Curve::scalar_test_bit(scalar, bit) {
                    index |= 1 << column;
                }
            }
            result = result.twice_plus(&self.points[index]);
        }
        Ok(result)
    }
}
