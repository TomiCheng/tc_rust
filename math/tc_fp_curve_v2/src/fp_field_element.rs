use tc_modular::PaddedMontyForm;

#[derive(Clone)]
pub struct FpFieldElement<'a> {
    value: PaddedMontyForm<'a>,
}

impl<'a> FpFieldElement<'a> {
    pub fn new(value: PaddedMontyForm<'a>) -> Self {
        Self { value }
    }
}
