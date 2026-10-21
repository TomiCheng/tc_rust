use crate::SecPCtCurve;
use crate::secp_element::SecPElement;
use tc_ec_core_v2::Point;

/// A point of a [`SecPCtCurve`], in homogeneous coordinates (X : Y : Z) for the complete
/// formulas, with infinity as (0 : 1 : 0).
#[derive(Clone)]
pub struct SecPCtPoint<'a, F> {
    curve: &'a SecPCtCurve<F>,
    x: F,
    y: F,
    z: F,
}

impl<'a, F: SecPElement> Point for SecPCtPoint<'a, F> {
    type Curve = &'a SecPCtCurve<F>;

    fn curve(&self) -> &'a SecPCtCurve<F> {
        self.curve
    }

    fn is_valid(&self) -> bool {
        todo!()
    }

    fn infinity(&self) -> Self {
        todo!()
    }

    fn is_infinity(&self) -> bool {
        todo!()
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

impl<F: SecPElement> PartialEq for SecPCtPoint<'_, F> {
    fn eq(&self, _rhs: &Self) -> bool {
        todo!()
    }
}

impl<F: SecPElement> Eq for SecPCtPoint<'_, F> {}
