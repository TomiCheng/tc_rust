use crate::sect_element::SecTElement;
use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
use tc_ec_core_v2::{BinaryFieldElement, FieldElement};

/// BC's `SecT233FieldElement`: GF(2^233) modulo x^233 + x^74 + 1.
#[derive(Clone)]
pub struct SecT233FieldElement {
    value: [u64; 4],
}

impl SecTElement for SecT233FieldElement {
    const M: usize = 233;

    fn zero() -> Self {
        todo!()
    }

    fn one() -> Self {
        todo!()
    }

    fn from_be(_bytes: &[u8]) -> Option<Self> {
        todo!()
    }

    fn invert_or_zero(&self) -> Self {
        todo!()
    }
}

impl FieldElement for SecT233FieldElement {
    fn is_zero(&self) -> bool {
        todo!()
    }

    fn is_one(&self) -> bool {
        todo!()
    }

    fn add(&self, _rhs: &Self) -> Self {
        todo!()
    }

    fn subtract(&self, _rhs: &Self) -> Self {
        todo!()
    }

    fn multiply(&self, _rhs: &Self) -> Self {
        todo!()
    }

    fn square(&self) -> Self {
        todo!()
    }

    fn sqrt(&self) -> Option<Self> {
        todo!()
    }

    fn negate(&self) -> Self {
        todo!()
    }

    fn invert(&self) -> Option<Self> {
        todo!()
    }

    fn encoded_length(&self) -> usize {
        todo!()
    }

    fn encode_to(&self, _output: &mut [u8]) {
        todo!()
    }
}

impl BinaryFieldElement for SecT233FieldElement {
    fn trace(&self) -> u8 {
        todo!()
    }

    fn half_trace(&self) -> Self {
        todo!()
    }
}

impl ConditionallySelectable for SecT233FieldElement {
    fn conditional_select(_a: &Self, _b: &Self, _choice: Choice) -> Self {
        todo!()
    }
}

impl ConstantTimeEq for SecT233FieldElement {
    fn ct_eq(&self, _rhs: &Self) -> Choice {
        todo!()
    }
}

impl PartialEq for SecT233FieldElement {
    fn eq(&self, rhs: &Self) -> bool {
        self.ct_eq(rhs).unwrap_u8() == 1
    }
}

impl Eq for SecT233FieldElement {}
