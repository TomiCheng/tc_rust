use crate::SecPVarPoint;
use crate::secp_element::SecPElement;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{CoordinateSystem, Curve};

/// A SEC prime curve over the field of `F`, in Jacobian coordinates as BC's `SecP*Curve`s
/// are; variable time, only for public values.
pub struct SecPVarCurve<F> {
    a: F,
    b: F,
    order: PaddedBigUint,
    cofactor: PaddedBigUint,
}

impl<F: SecPElement> SecPVarCurve<F> {
    pub(crate) fn new(a: F, b: F, order: PaddedBigUint, cofactor: PaddedBigUint) -> Self {
        Self {
            a,
            b,
            order,
            cofactor,
        }
    }
}

impl<'a, F: SecPElement> Curve for &'a SecPVarCurve<F> {
    type Field = F;
    type Point = SecPVarPoint<'a, F>;
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

    fn infinity(&self) -> SecPVarPoint<'a, F> {
        todo!()
    }

    fn create_point(&self, _x: F, _y: F) -> SecPVarPoint<'a, F> {
        todo!()
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        CoordinateSystem::Jacobian
    }

    fn multiply(_point: &SecPVarPoint<'a, F>, _scalar: &PaddedBigUint) -> SecPVarPoint<'a, F> {
        todo!()
    }
}
