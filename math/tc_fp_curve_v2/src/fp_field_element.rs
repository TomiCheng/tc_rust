use tc_modular::PaddedMontyForm;

#[derive(Clone)]
pub struct FpFieldElement<'a> {
    value: PaddedMontyForm<'a>,
}
