use crate::SecPCtPoint;
use crate::secp_element::SecPElement;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{CoordinateSystem, Curve};

/// A SEC prime curve over the field of `F`, whose multiplication is constant time.
pub struct SecPCtCurve<F> {
    a: F,
    b: F,
    order: PaddedBigUint,
    cofactor: PaddedBigUint,
}

impl<F: SecPElement> SecPCtCurve<F> {
    pub(crate) fn new(a: F, b: F, order: PaddedBigUint, cofactor: PaddedBigUint) -> Self {
        Self {
            a,
            b,
            order,
            cofactor,
        }
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
        todo!()
    }

    fn create_point(&self, _x: F, _y: F) -> SecPCtPoint<'a, F> {
        todo!()
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        CoordinateSystem::Homogeneous
    }

    fn multiply(_point: &SecPCtPoint<'a, F>, _scalar: &PaddedBigUint) -> SecPCtPoint<'a, F> {
        todo!()
    }
}
