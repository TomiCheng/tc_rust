use crate::{F2mCurve, F2mFieldElement};

#[derive(Clone)]
pub struct F2mPoint<'a> {
    curve: &'a F2mCurve,
    x: F2mFieldElement,
    y: F2mFieldElement,
}
