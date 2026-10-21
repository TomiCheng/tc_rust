use crate::SecPCtPoint;
use crate::secp_element::SecPElement;
use crate::{SecPError, sec1};
use core::fmt;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{CoordinateSystem, Curve, PointDecodeError};

/// A SEC prime curve over the field of `F`, whose points take only constant-time formulas:
/// the complete formulas of Renes, Costello and Batina (2016) in homogeneous coordinates,
/// complete on these curves of prime order.
pub struct SecPCtCurve<F> {
    a: F,
    b: F,
    b3: F,
    order: PaddedBigUint,
    cofactor: PaddedBigUint,
}

impl<F: SecPElement> SecPCtCurve<F> {
    pub(crate) fn new(a: F, b: F, order: PaddedBigUint, cofactor: PaddedBigUint) -> Self {
        Self {
            a,
            b3: b.add(&b).add(&b),
            b,
            order,
            cofactor,
        }
    }

    pub(crate) fn b3(&self) -> &F {
        &self.b3
    }

    pub fn infinity(&self) -> SecPCtPoint<'_, F> {
        SecPCtPoint::infinity(self)
    }

    /// The point `(x, y)` from SEC 1 octet strings, which is not checked against the curve.
    pub fn create_point(&self, x: &[u8], y: &[u8]) -> Result<SecPCtPoint<'_, F>, SecPError> {
        Ok(SecPCtPoint::new(self, sec1::element(x)?, sec1::element(y)?))
    }

    /// The bytes of one coordinate in the SEC 1 encoding.
    pub fn field_element_encoding_length(&self) -> usize {
        sec1::coordinate_length::<F>()
    }

    /// The bytes of the SEC 1 encoding of a finite point.
    pub fn affine_point_encoding_length(&self, compressed: bool) -> usize {
        sec1::point_length::<F>(compressed)
    }

    /// Decodes the SEC 1 infinity, compressed, uncompressed and hybrid forms, and checks
    /// that the point is on the curve; the subgroup is not checked, as in BC. An encoding
    /// is public: this is variable time in it, as decompression takes a square root.
    pub fn decode_point(&self, encoded: &[u8]) -> Result<SecPCtPoint<'_, F>, PointDecodeError> {
        Ok(match sec1::decode(&self.a, &self.b, encoded)? {
            None => self.infinity(),
            Some((x, y)) => SecPCtPoint::new(self, x, y),
        })
    }
}

impl<'a, F: SecPElement> Curve for &'a SecPCtCurve<F> {
    type Field = F;
    type Point = SecPCtPoint<'a, F>;
    type Scalar = PaddedBigUint;

    fn a(&self) -> &F {
        &self.a
    }

    fn b(&self) -> &F {
        &self.b
    }

    fn order(&self) -> Option<&PaddedBigUint> {
        Some(&self.order)
    }

    fn cofactor(&self) -> Option<&PaddedBigUint> {
        Some(&self.cofactor)
    }

    fn zero(&self) -> F {
        F::zero()
    }

    fn one(&self) -> F {
        F::one()
    }

    fn infinity(&self) -> SecPCtPoint<'a, F> {
        SecPCtPoint::infinity(self)
    }

    fn create_point(&self, x: F, y: F) -> SecPCtPoint<'a, F> {
        SecPCtPoint::new(self, x, y)
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        CoordinateSystem::Homogeneous
    }

    /// The fixed-window multiplication of [`SecPCtPoint::multiply`]. Constant time.
    fn multiply(point: &SecPCtPoint<'a, F>, scalar: &PaddedBigUint) -> SecPCtPoint<'a, F> {
        point.multiply(scalar)
    }
}

/// The same coefficients, as in BC; the order and cofactor are left out.
impl<F: SecPElement> PartialEq for SecPCtCurve<F> {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}

impl<F: SecPElement> Eq for SecPCtCurve<F> {}

impl<F> fmt::Debug for SecPCtCurve<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecPCtCurve").finish_non_exhaustive()
    }
}
