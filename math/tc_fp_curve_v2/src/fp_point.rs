use crate::{FpCurve, FpFieldElement};

#[derive(Clone)]
pub struct FpPoint<'a> {
    curve: &'a FpCurve<'a>,
    x: FpFieldElement<'a>,
    y: FpFieldElement<'a>,
}
