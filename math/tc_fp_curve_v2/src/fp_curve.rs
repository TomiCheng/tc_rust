use crate::{FpField, FpFieldElement};

pub struct FpCurve<'a> {
    field: &'a FpField,
    a: FpFieldElement<'a>,
    b: FpFieldElement<'a>,
}
