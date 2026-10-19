use crate::SecTVarPoint;
use crate::sect_element::SecTElement;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{CoordinateSystem, Curve};

/// A SEC binary curve over the field of `F`, in lambda-projective coordinates as BC's
/// `SecT*Curve`s are; variable time, only for public values.
pub struct SecTVarCurve<F> {
    a: F,
    b: F,
    order: PaddedBigUint,
    cofactor: PaddedBigUint,
}

impl<F: SecTElement> SecTVarCurve<F> {
    pub(crate) fn new(a: F, b: F, order: PaddedBigUint, cofactor: PaddedBigUint) -> Self {
        Self {
            a,
            b,
            order,
            cofactor,
        }
    }
}

impl<'a, F: SecTElement> Curve for &'a SecTVarCurve<F> {
    type Field = F;
    type Point = SecTVarPoint<'a, F>;
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

    fn infinity(&self) -> SecTVarPoint<'a, F> {
        todo!()
    }

    fn create_point(&self, _x: F, _y: F) -> SecTVarPoint<'a, F> {
        todo!()
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        CoordinateSystem::LambdaProjective
    }

    fn multiply(_point: &SecTVarPoint<'a, F>, _scalar: &PaddedBigUint) -> SecTVarPoint<'a, F> {
        todo!()
    }
}
