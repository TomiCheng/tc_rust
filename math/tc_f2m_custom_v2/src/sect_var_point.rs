use crate::SecTVarCurve;
use crate::sect_element::SecTElement;
use tc_ec_core_v2::Point;

/// A point of a [`SecTVarCurve`], in lambda-projective coordinates (X, L, Z).
#[derive(Clone)]
pub struct SecTVarPoint<'a, F> {
    curve: &'a SecTVarCurve<F>,
    xlz: Option<(F, F, F)>,
}

impl<'a, F: SecTElement> Point for SecTVarPoint<'a, F> {
    type Curve = &'a SecTVarCurve<F>;

    fn curve(&self) -> &'a SecTVarCurve<F> {
        self.curve
    }

    fn is_valid(&self) -> bool {
        todo!()
    }

    fn infinity(&self) -> Self {
        todo!()
    }

    fn is_infinity(&self) -> bool {
        self.xlz.is_none()
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

impl<F: SecTElement> PartialEq for SecTVarPoint<'_, F> {
    fn eq(&self, _rhs: &Self) -> bool {
        todo!()
    }
}

impl<F: SecTElement> Eq for SecTVarPoint<'_, F> {}
