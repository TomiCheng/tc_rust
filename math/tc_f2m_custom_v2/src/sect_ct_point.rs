use crate::SecTCtCurve;
use crate::sect_element::SecTElement;
use tc_ec_core_v2::Point;

/// A point of a [`SecTCtCurve`], in affine coordinates.
#[derive(Clone)]
pub struct SecTCtPoint<'a, F> {
    curve: &'a SecTCtCurve<F>,
    xy: Option<(F, F)>,
}

impl<'a, F: SecTElement> Point for SecTCtPoint<'a, F> {
    type Curve = &'a SecTCtCurve<F>;

    fn curve(&self) -> &'a SecTCtCurve<F> {
        self.curve
    }

    fn is_valid(&self) -> bool {
        todo!()
    }

    fn infinity(&self) -> Self {
        todo!()
    }

    fn is_infinity(&self) -> bool {
        self.xy.is_none()
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

impl<F: SecTElement> PartialEq for SecTCtPoint<'_, F> {
    fn eq(&self, _rhs: &Self) -> bool {
        todo!()
    }
}

impl<F: SecTElement> Eq for SecTCtPoint<'_, F> {}
