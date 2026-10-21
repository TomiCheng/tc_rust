use crate::SecPVarCurve;
use crate::secp_element::SecPElement;
use tc_ec_core_v2::Point;

/// A point of a [`SecPVarCurve`], in Jacobian coordinates (X, Y, Z).
#[derive(Clone)]
pub struct SecPVarPoint<'a, F> {
    curve: &'a SecPVarCurve<F>,
    xyz: Option<(F, F, F)>,
}

impl<'a, F: SecPElement> Point for SecPVarPoint<'a, F> {
    type Curve = &'a SecPVarCurve<F>;

    fn curve(&self) -> &'a SecPVarCurve<F> {
        self.curve
    }

    fn is_valid(&self) -> bool {
        todo!()
    }

    fn infinity(&self) -> Self {
        todo!()
    }

    fn is_infinity(&self) -> bool {
        self.xyz.is_none()
    }

    fn x(&self) -> Option<F> {
        todo!()
    }

    fn y(&self) -> Option<F> {
        todo!()
    }

    fn add(&self, _rhs: &Self) -> Self {
        todo!()
    }

    fn twice(&self) -> Self {
        todo!()
    }

    fn negate(&self) -> Self {
        todo!()
    }

    fn normalize(&self) -> Self {
        todo!()
    }

    fn projective_z(&self) -> Option<F> {
        todo!()
    }

    fn normalize_with_inverse(&self, _inverse: &F) -> Self {
        todo!()
    }
}

impl<F: SecPElement> PartialEq for SecPVarPoint<'_, F> {
    fn eq(&self, _rhs: &Self) -> bool {
        todo!()
    }
}

impl<F: SecPElement> Eq for SecPVarPoint<'_, F> {}
