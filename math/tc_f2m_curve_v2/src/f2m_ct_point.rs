use crate::{F2mCtCurve, F2mFieldElement};

#[derive(Clone)]
pub struct F2mCtPoint<'a> {
    curve: &'a F2mCtCurve,
    x: F2mFieldElement,
    y: F2mFieldElement,
}
