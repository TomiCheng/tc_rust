use crate::{F2mFieldElement, F2mVarCurve};

#[derive(Clone)]
pub struct F2mVarPoint<'a> {
    curve: &'a F2mVarCurve,
    x: F2mFieldElement,
    y: F2mFieldElement,
}
