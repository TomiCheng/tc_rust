use crate::secp_element::SecPElement;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{FieldElement, PrimeFieldElement};

/// BC's `SecP384R1FieldElement`: GF(p) for p = 2^384 - 2^128 - 2^96 + 2^32 - 1, on twelve
/// 32-bit limbs.
#[derive(Clone)]
pub struct SecP384R1FieldElement {
    value: [u32; 12],
}

impl SecPElement for SecP384R1FieldElement {
    fn zero() -> Self {
        todo!()
    }

    fn one() -> Self {
        todo!()
    }

    fn from_be(_bytes: &[u8]) -> Option<Self> {
        todo!()
    }
}

impl FieldElement for SecP384R1FieldElement {
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
        48
    }

    fn encode_to(&self, _output: &mut [u8]) {
        todo!()
    }
}

impl PrimeFieldElement for SecP384R1FieldElement {
    type BigUint = PaddedBigUint;

    fn element_from_big_uint(&self, _value: &PaddedBigUint) -> Self {
        todo!()
    }

    fn to_big_uint(&self) -> PaddedBigUint {
        todo!()
    }
}

impl PartialEq for SecP384R1FieldElement {
    fn eq(&self, _rhs: &Self) -> bool {
        todo!()
    }
}

impl Eq for SecP384R1FieldElement {}
