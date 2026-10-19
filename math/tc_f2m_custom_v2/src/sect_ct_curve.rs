use crate::SecTCtPoint;
use crate::sect_element::SecTElement;
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
        todo!()
    }

    fn create_point(&self, _x: F, _y: F) -> SecTCtPoint<'a, F> {
        todo!()
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        CoordinateSystem::Affine
    }

    fn multiply(_point: &SecTCtPoint<'a, F>, _scalar: &PaddedBigUint) -> SecTCtPoint<'a, F> {
        todo!()
    }
}
