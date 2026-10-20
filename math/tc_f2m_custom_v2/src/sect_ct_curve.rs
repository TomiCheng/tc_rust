use crate::SecTCtPoint;
use crate::sect_element::SecTElement;
use core::fmt;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{CoordinateSystem, Curve};

/// A SEC binary curve over the field of `F`, whose multiplication is constant time.
pub struct SecTCtCurve<F> {
    a: F,
    b: F,
    order: PaddedBigUint,
    cofactor: PaddedBigUint,
}

impl<F: SecTElement> SecTCtCurve<F> {
    pub(crate) fn new(a: F, b: F, order: PaddedBigUint, cofactor: PaddedBigUint) -> Self {
        Self {
            a,
            b,
            order,
            cofactor,
        }
    }
}

impl<'a, F: SecTElement> Curve for &'a SecTCtCurve<F> {
    type Field = F;
    type Point = SecTCtPoint<'a, F>;
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

    fn infinity(&self) -> SecTCtPoint<'a, F> {
        SecTCtPoint::infinity(self)
    }

    fn create_point(&self, x: F, y: F) -> SecTCtPoint<'a, F> {
        SecTCtPoint::new(self, x, y)
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        CoordinateSystem::Affine
    }

    /// The Montgomery ladder of [`SecTCtPoint::multiply`]. Constant time.
    fn multiply(point: &SecTCtPoint<'a, F>, scalar: &PaddedBigUint) -> SecTCtPoint<'a, F> {
        point.multiply(scalar)
    }
}

/// The same coefficients, as in BC; the order and cofactor are left out.
impl<F: SecTElement> PartialEq for SecTCtCurve<F> {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}

impl<F: SecTElement> Eq for SecTCtCurve<F> {}

impl<F> fmt::Debug for SecTCtCurve<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecTCtCurve").finish_non_exhaustive()
    }
}
