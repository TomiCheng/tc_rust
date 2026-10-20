use crate::sect_element::SecTElement;
use crate::sect571_field;
use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
use tc_ec_core_v2::{BinaryFieldElement, FieldElement};
use tc_zeroize::Zeroize;

const LENGTH: usize = 72;

/// BC's `SecT571FieldElement`: GF(2^571) modulo x^571 + x^10 + x^5 + x^2 + 1. Wiped on drop.
#[derive(Clone)]
pub struct SecT571FieldElement {
    value: [u64; 9],
}

impl SecTElement for SecT571FieldElement {
    const M: usize = 571;

    fn zero() -> Self {
        Self { value: [0; 9] }
    }

    fn one() -> Self {
        let mut value = [0; 9];
        value[0] = 1;
        Self { value }
    }

    fn from_be(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != LENGTH || bytes[0] >> 3 != 0 {
            return None;
        }
        let mut value = [0; 9];
        for (i, &byte) in bytes.iter().rev().enumerate() {
            value[i / 8] |= u64::from(byte) << (8 * (i % 8));
        }
        Some(Self { value })
    }

    fn invert_or_zero(&self) -> Self {
        Self {
            value: sect571_field::invert(&self.value),
        }
    }

    fn low_bit(&self) -> u8 {
        (self.value[0] & 1) as u8
    }
}

/// Constant time on a CPU with PCLMULQDQ; without it the multiplication indexes a table by
/// operand bits, a cache-timing side channel.
impl FieldElement for SecT571FieldElement {
    fn is_zero(&self) -> bool {
        self.value.iter().fold(0, |acc, &limb| acc | limb) == 0
    }

    fn is_one(&self) -> bool {
        self.value[1..]
            .iter()
            .fold(self.value[0] ^ 1, |acc, &limb| acc | limb)
            == 0
    }

    fn add(&self, rhs: &Self) -> Self {
        Self {
            value: sect571_field::add(&self.value, &rhs.value),
        }
    }

    fn subtract(&self, rhs: &Self) -> Self {
        self.add(rhs)
    }

    fn multiply(&self, rhs: &Self) -> Self {
        Self {
            value: sect571_field::multiply(&self.value, &rhs.value),
        }
    }

    fn square(&self) -> Self {
        Self {
            value: sect571_field::square(&self.value),
        }
    }

    fn sqrt(&self) -> Option<Self> {
        Some(Self {
            value: sect571_field::sqrt(&self.value),
        })
    }

    fn negate(&self) -> Self {
        self.clone()
    }

    /// `None` for zero, which is all the running time tells.
    fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(Self {
            value: sect571_field::invert(&self.value),
        })
    }

    fn encoded_length(&self) -> usize {
        LENGTH
    }

    fn encode_to(&self, output: &mut [u8]) {
        assert_eq!(output.len(), LENGTH, "the output is the encoded length");
        for (i, byte) in output.iter_mut().rev().enumerate() {
            *byte = (self.value[i / 8] >> (8 * (i % 8))) as u8;
        }
    }
}

impl BinaryFieldElement for SecT571FieldElement {
    fn trace(&self) -> u8 {
        sect571_field::trace(&self.value)
    }

    fn half_trace(&self) -> Self {
        Self {
            value: sect571_field::half_trace(&self.value),
        }
    }
}

impl ConditionallySelectable for SecT571FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            value: <[u64; 9]>::conditional_select(&a.value, &b.value, choice),
        }
    }
}

impl ConstantTimeEq for SecT571FieldElement {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.value.ct_eq(&rhs.value)
    }
}

impl PartialEq for SecT571FieldElement {
    fn eq(&self, rhs: &Self) -> bool {
        self.ct_eq(rhs).unwrap_u8() == 1
    }
}

impl Eq for SecT571FieldElement {}

impl Drop for SecT571FieldElement {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::{LENGTH, SecT571FieldElement};
    use crate::sect_element::SecTElement;
    use tc_binpoly::{BinField, PaddedBinPoly};
    use tc_ec_core_v2::{BinaryFieldElement, FieldElement};

    // splitmix64, for inputs that differ run to run of the loop but not of the test.
    fn element(state: &mut u64) -> [u8; LENGTH] {
        let mut bytes = [0; LENGTH];
        for byte in &mut bytes {
            *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *byte = (z ^ (z >> 31)) as u8;
        }
        bytes[0] &= 0x07;
        bytes
    }

    fn encode(x: &SecT571FieldElement) -> [u8; LENGTH] {
        let mut bytes = [0; LENGTH];
        x.encode_to(&mut bytes);
        bytes
    }

    #[test]
    fn sums_products_and_squares_match_the_generic_field() {
        let field = BinField::pentanomial(571, 2, 5, 10).unwrap();
        let mut state = 0x023b;
        for _ in 0..200 {
            let (a, b) = (element(&mut state), element(&mut state));
            let (x, y) = (
                SecT571FieldElement::from_be(&a).unwrap(),
                SecT571FieldElement::from_be(&b).unwrap(),
            );
            let (p, q) = (
                PaddedBinPoly::from_be(field, &a).unwrap(),
                PaddedBinPoly::from_be(field, &b).unwrap(),
            );

            assert_eq!(encode(&x), a);
            assert_eq!(encode(&x.add(&y)).to_vec(), p.add(&q).to_be());
            assert_eq!(encode(&x.multiply(&y)).to_vec(), p.multiply(&q).to_be());
            assert_eq!(encode(&x.square()).to_vec(), p.square().to_be());
        }
    }

    // Tr(x) = x + x^2 + x^4 + ... + x^(2^570), worked out the long way.
    #[test]
    fn the_trace_matches_its_definition() {
        let mut state = 0x7ACE;
        for _ in 0..20 {
            let x = SecT571FieldElement::from_be(&element(&mut state)).unwrap();
            let (mut power, mut sum) = (x.clone(), x.clone());
            for _ in 1..571 {
                power = power.square();
                sum = sum.add(&power);
            }
            assert!(sum.is_zero() || sum.is_one());
            assert_eq!(x.trace(), u8::from(sum.is_one()));
        }
    }

    #[test]
    fn roots_inverses_and_half_traces_undo_what_they_should() {
        let one = SecT571FieldElement::one();
        let mut state = 0x5157;
        for _ in 0..50 {
            let x = SecT571FieldElement::from_be(&element(&mut state)).unwrap();
            assert!(x.sqrt().unwrap().square() == x);
            if !x.is_zero() {
                assert!(x.invert().unwrap().multiply(&x) == one);
            }
            let h = x.half_trace();
            let trace = [SecT571FieldElement::zero(), one.clone()][usize::from(x.trace())].clone();
            assert!(h.square().add(&h) == x.add(&trace));
        }
        assert!(SecT571FieldElement::zero().invert().is_none());
    }

    #[test]
    fn bytes_out_of_the_field_are_refused() {
        let mut bytes = [0; LENGTH];
        bytes[0] = 0x08;
        assert!(SecT571FieldElement::from_be(&bytes).is_none());
        assert!(SecT571FieldElement::from_be(&bytes[1..]).is_none());
        bytes[0] = 0x07;
        assert!(SecT571FieldElement::from_be(&bytes).is_some());
    }
}
