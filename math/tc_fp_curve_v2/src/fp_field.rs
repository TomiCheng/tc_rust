use crate::FpFieldElement;
use tc_bigint::PaddedBigUint;
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};

pub struct FpField {
    params: PaddedMontyParams,
}

impl FpField {
    /// The field of integers modulo the prime `q`, at the width of `q`. Panics when `q` is even.
    pub fn new(q: PaddedBigUint) -> Self {
        let modulus = Odd::new(q).expect("curve prime is odd");
        Self {
            params: PaddedMontyParams::new(modulus),
        }
    }

    pub(crate) fn q(&self) -> &PaddedBigUint {
        self.params.modulus()
    }

    pub(crate) fn element(&self, value: &PaddedBigUint) -> FpFieldElement<'_> {
        assert!(value < self.q(), "value invalid for Fp field element");
        let value = PaddedMontyForm::new(value, &self.params);
        FpFieldElement::new(value)
    }

    pub(crate) fn one(&self) -> FpFieldElement<'_> {
        FpFieldElement::new(PaddedMontyForm::one(&self.params))
    }
}

impl PartialEq for FpField {
    fn eq(&self, other: &Self) -> bool {
        let (lhs, rhs) = (self.q(), other.q());
        lhs.as_limbs().len() == rhs.as_limbs().len() && lhs == rhs
    }
}

impl Eq for FpField {}

impl core::fmt::Debug for FpField {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FpField")
            .field("q", &format_args!("{:#x}", self.q()))
            .field("limbs", &self.q().as_limbs().len())
            .finish()
    }
}
