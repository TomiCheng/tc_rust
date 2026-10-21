use crate::nat;
use crate::secp_element::SecPElement;
use crate::secp256r1_field::{self, P};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
use tc_ec_core_v2::{FieldElement, PrimeFieldElement};
use tc_zeroize::Zeroize;

const LENGTH: usize = 32;

/// BC's `SecP256R1FieldElement`: GF(p) for p = 2^256 - 2^224 + 2^192 + 2^96 - 1, on eight
/// 32-bit limbs. Wiped on drop.
#[derive(Clone)]
pub struct SecP256R1FieldElement {
    value: [u32; 8],
}

impl SecPElement for SecP256R1FieldElement {
    const LENGTH: usize = LENGTH;

    fn zero() -> Self {
        Self { value: [0; 8] }
    }

    fn one() -> Self {
        let mut value = [0; 8];
        value[0] = 1;
        Self { value }
    }

    fn from_be(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != LENGTH {
            return None;
        }
        let value = nat::from_be(bytes);
        (nat::sub(&value, &P).1 == 1).then_some(Self { value })
    }

    fn low_bit(&self) -> u8 {
        (self.value[0] & 1) as u8
    }
}

/// Constant time, apart from the `bool` and `Option` answers.
impl FieldElement for SecP256R1FieldElement {
    fn is_zero(&self) -> bool {
        nat::is_zero(&self.value) == 1
    }

    fn is_one(&self) -> bool {
        *self == Self::one()
    }

    fn add(&self, rhs: &Self) -> Self {
        Self {
            value: nat::add_mod(&self.value, &rhs.value, &P),
        }
    }

    fn subtract(&self, rhs: &Self) -> Self {
        Self {
            value: nat::sub_mod(&self.value, &rhs.value, &P),
        }
    }

    fn multiply(&self, rhs: &Self) -> Self {
        Self {
            value: secp256r1_field::multiply(&self.value, &rhs.value),
        }
    }

    fn square(&self) -> Self {
        Self {
            value: secp256r1_field::square(&self.value),
        }
    }

    fn sqrt(&self) -> Option<Self> {
        let root = Self {
            value: secp256r1_field::sqrt(&self.value),
        };
        (root.square() == *self).then_some(root)
    }

    fn negate(&self) -> Self {
        Self {
            value: nat::sub_mod(&[0; 8], &self.value, &P),
        }
    }

    fn invert(&self) -> Option<Self> {
        (!self.is_zero()).then(|| Self {
            value: secp256r1_field::invert(&self.value),
        })
    }

    fn encoded_length(&self) -> usize {
        LENGTH
    }

    fn encode_to(&self, output: &mut [u8]) {
        assert_eq!(output.len(), LENGTH, "a field element takes 32 bytes");
        nat::to_be(&self.value, output);
    }
}

/// Constant time in the value, whose width is public.
impl PrimeFieldElement for SecP256R1FieldElement {
    type BigUint = PaddedBigUint;

    fn element_from_big_uint(&self, value: &PaddedBigUint) -> Self {
        let mut bytes = ArrayEncoding::<u8>::to_be(value);
        let value = nat::reduce_be(&bytes, &P, secp256r1_field::multiply);
        bytes.zeroize();
        Self { value }
    }

    fn to_big_uint(&self) -> PaddedBigUint {
        let mut bytes = [0; LENGTH];
        self.encode_to(&mut bytes);
        let value = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes)
            .expect("32 bytes make an integer");
        bytes.zeroize();
        value
    }
}

impl ConditionallySelectable for SecP256R1FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            value: <[u32; 8]>::conditional_select(&a.value, &b.value, choice),
        }
    }
}

impl ConstantTimeEq for SecP256R1FieldElement {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.value.ct_eq(&rhs.value)
    }
}

impl PartialEq for SecP256R1FieldElement {
    fn eq(&self, rhs: &Self) -> bool {
        self.ct_eq(rhs).unwrap_u8() == 1
    }
}

impl Eq for SecP256R1FieldElement {}

impl Drop for SecP256R1FieldElement {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::{LENGTH, SecP256R1FieldElement};
    use crate::secp_element::SecPElement;
    use alloc::vec::Vec;
    use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
    use tc_ec_core_v2::{FieldElement, PrimeFieldElement};

    const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn big(bytes: &[u8]) -> BigUint {
        <BigUint as ArrayEncoding<u8>>::from_be(bytes).unwrap()
    }

    // splitmix64, reduced below p by the oracle.
    fn element(state: &mut u64) -> [u8; LENGTH] {
        let mut bytes = [0; LENGTH];
        for byte in &mut bytes {
            *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *byte = (z ^ (z >> 31)) as u8;
        }
        let reduced = big(&bytes) % big(&hex(P));
        encode_big(&reduced)
    }

    fn encode_big(value: &BigUint) -> [u8; LENGTH] {
        let bytes = ArrayEncoding::<u8>::to_be(value);
        let mut out = [0; LENGTH];
        out[LENGTH - bytes.len()..].copy_from_slice(&bytes);
        out
    }

    fn encode(x: &SecP256R1FieldElement) -> [u8; LENGTH] {
        let mut bytes = [0; LENGTH];
        x.encode_to(&mut bytes);
        bytes
    }

    fn edges() -> Vec<[u8; LENGTH]> {
        let p = big(&hex(P));
        [0u32, 1, 2]
            .iter()
            .map(|&k| encode_big(&BigUint::from(k)))
            .chain(
                [1u32, 2]
                    .iter()
                    .map(|&k| encode_big(&(p.clone() - BigUint::from(k)))),
            )
            .collect()
    }

    #[test]
    fn sums_differences_products_and_squares_match_big_integers() {
        let p = big(&hex(P));
        let mut state = 0x0256;
        let mut inputs = edges();
        inputs.extend((0..200).map(|_| element(&mut state)));
        for (i, a) in inputs.iter().enumerate() {
            let b = &inputs[(i * 7 + 3) % inputs.len()];
            let (x, y) = (
                SecP256R1FieldElement::from_be(a).unwrap(),
                SecP256R1FieldElement::from_be(b).unwrap(),
            );
            let (m, n) = (big(a), big(b));
            assert_eq!(encode(&x), *a);
            assert_eq!(encode(&x.add(&y)), encode_big(&((m.clone() + &n) % &p)));
            assert_eq!(
                encode(&x.subtract(&y)),
                encode_big(&((m.clone() + &p - &n) % &p))
            );
            assert_eq!(encode(&x.negate()), encode_big(&((p.clone() - &m) % &p)));
            assert_eq!(
                encode(&x.multiply(&y)),
                encode_big(&((m.clone() * &n) % &p))
            );
            assert_eq!(encode(&x.square()), encode_big(&((m.clone() * &m) % &p)));
        }
    }

    #[test]
    fn roots_and_inverses_undo_what_they_should() {
        let one = SecP256R1FieldElement::one();
        let mut state = 0x5157;
        let mut squares = 0;
        for _ in 0..50 {
            let x = SecP256R1FieldElement::from_be(&element(&mut state)).unwrap();
            if let Some(root) = x.sqrt() {
                assert!(root.square() == x);
                squares += 1;
            }
            assert!(x.square().sqrt().unwrap().square() == x.square());
            if !x.is_zero() {
                assert!(x.invert().unwrap().multiply(&x) == one);
            }
        }
        assert!(squares > 10 && squares < 40);
        assert!(SecP256R1FieldElement::zero().invert().is_none());
    }

    #[test]
    fn big_integers_convert_both_ways_and_reduce_past_p() {
        let mut state = 0xB16;
        let p = PaddedBigUint::from_be(&hex(P)).unwrap();
        let x = SecP256R1FieldElement::from_be(&element(&mut state)).unwrap();
        let value = x.to_big_uint();
        assert!(x.element_from_big_uint(&value) == x);
        assert!(x.element_from_big_uint(&p).is_zero());
        let wide = PaddedBigUint::from_be(&[&[1u8][..], &hex(P)].concat()).unwrap();
        // 2^256 + p = 2^256 = 2^224 - 2^192 - 2^96 + 1 mod p
        let expected = "00000000fffffffeffffffffffffffffffffffff000000000000000000000001";
        assert_eq!(
            encode(&x.element_from_big_uint(&wide)).to_vec(),
            hex(expected)
        );
    }

    #[test]
    fn bytes_out_of_the_field_are_refused() {
        let p = hex(P);
        assert!(SecP256R1FieldElement::from_be(&p).is_none());
        assert!(SecP256R1FieldElement::from_be(&p[1..]).is_none());
        assert!(SecP256R1FieldElement::from_be(&[0xff; LENGTH]).is_none());
        let mut below = p.clone();
        below[LENGTH - 1] -= 1;
        assert!(SecP256R1FieldElement::from_be(&below).is_some());
    }
}
