use crate::{F2mCtCurve, F2mFieldElement};

/// A point on an [`F2mCtCurve`] in affine coordinates, `None` for infinity.
#[derive(Clone)]
pub struct F2mCtPoint<'a> {
    curve: &'a F2mCtCurve,
    coords: Option<(F2mFieldElement, F2mFieldElement)>,
}

impl<'a> F2mCtPoint<'a> {
    pub(crate) fn new(curve: &'a F2mCtCurve, x: F2mFieldElement, y: F2mFieldElement) -> Self {
        Self {
            curve,
            coords: Some((x, y)),
        }
    }

    pub(crate) fn infinity(curve: &'a F2mCtCurve) -> Self {
        Self {
            curve,
            coords: None,
        }
    }
}
