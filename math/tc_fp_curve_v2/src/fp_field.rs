use crate::{FpError, FpFieldElement};
use tc_bigint::PaddedBigUint;
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};

pub struct FpField {
    params: PaddedMontyParams,
}

impl FpField {
    /// The field of integers modulo the prime `q`, at the width of `q`. `q` is not checked
    /// to be prime, only to be odd, as Montgomery arithmetic needs. Variable time; only
    /// for a public modulus.
    pub fn new(q: PaddedBigUint) -> Result<Self, FpError> {
        let modulus = Odd::new(q).ok_or(FpError::EvenModulus)?;
        Ok(Self {
            params: PaddedMontyParams::new(modulus),
        })
    }

    pub(crate) fn q(&self) -> &PaddedBigUint {
        self.params.modulus()
    }

    pub(crate) fn element(&self, value: &PaddedBigUint) -> Result<FpFieldElement<'_>, FpError> {
        if value >= self.q() {
            return Err(FpError::NotBelowModulus);
        }
        Ok(FpFieldElement::new(PaddedMontyForm::new(
            value,
            &self.params,
        )))
    }

    pub(crate) fn zero(&self) -> FpFieldElement<'_> {
        FpFieldElement::new(PaddedMontyForm::zero(&self.params))
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
