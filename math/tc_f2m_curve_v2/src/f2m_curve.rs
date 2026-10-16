use crate::{F2mField, F2mFieldElement};

pub struct F2mCurve {
    field: F2mField,
    a: F2mFieldElement,
    b: F2mFieldElement,
}
