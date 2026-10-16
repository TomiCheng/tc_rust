use tc_binpoly_v2::PaddedBinPoly;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct F2mFieldElement {
    value: PaddedBinPoly,
}

impl F2mFieldElement {
    pub(crate) fn new(value: PaddedBinPoly) -> Self {
        Self { value }
    }
}
