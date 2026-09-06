//! Portable fixed-schedule arithmetic for secret operands. The fast Solinas
//! backends remain available for public operations; their carry loops vary.
use crate::specialized_curve::SpecializedCurve;
use crate::specialized_field::{PrimeFieldSpec, SpecializedFieldElement};
use crate::{SecP256R1Curve, SecP256R1Field, SecP256R1FieldElement};
use tc_ec_core::{Choice, ConditionallySelectable, ConstantTimeEq, SecretCurve, SecretField};

fn subtract<const N: usize>(a: &[u32; N], b: &[u32; N]) -> ([u32; N], u8) {
    let mut borrow = 0_i64;
    let result = core::array::from_fn(|i| {
        let value = a[i] as i64 - b[i] as i64 - borrow;
        borrow = (value >> 63) & 1;
        value as u32
    });
    (result, borrow as u8)
}
fn add<const N: usize>(a: &[u32; N], b: &[u32; N], p: &[u32; N]) -> [u32; N] {
    let mut carry = 0_u64;
    let sum = core::array::from_fn(|i| {
        let value = a[i] as u64 + b[i] as u64 + carry;
        carry = value >> 32;
        value as u32
    });
    let (reduced, borrow) = subtract(&sum, p);
    <[u32; N]>::conditional_select(&sum, &reduced, Choice::from_lsb(carry as u8 | (borrow ^ 1)))
}
fn sub<const N: usize>(a: &[u32; N], b: &[u32; N], p: &[u32; N]) -> [u32; N] {
    let (difference, borrow) = subtract(a, b);
    let mut carry = 0_u64;
    let corrected = core::array::from_fn(|i| {
        let value = difference[i] as u64 + p[i] as u64 + carry;
        carry = value >> 32;
        value as u32
    });
    <[u32; N]>::conditional_select(&difference, &corrected, Choice::from_lsb(borrow))
}
fn mul<const N: usize>(a: &[u32; N], b: &[u32; N], p: &[u32; N]) -> [u32; N] {
    let mut result = [0; N];
    for word in b.iter().rev() {
        for bit in (0..32).rev() {
            result = add(&result, &result, p);
            let next = add(&result, a, p);
            result = <[u32; N]>::conditional_select(
                &result,
                &next,
                Choice::from_lsb((word >> bit) as u8),
            );
        }
    }
    result
}
fn inverse<const N: usize>(a: &[u32; N], p: &[u32; N]) -> [u32; N] {
    let mut two = [0; N];
    two[0] = 2;
    let exponent = subtract(p, &two).0;
    let mut result = [0; N];
    result[0] = 1;
    for word in exponent.iter().rev() {
        for bit in (0..32).rev() {
            result = mul(&result, &result, p);
            // Exponent is the public field modulus minus two.
            if word >> bit & 1 != 0 {
                result = mul(&result, a, p);
            }
        }
    }
    result
}

impl<S: PrimeFieldSpec<N>, const N: usize> ConditionallySelectable
    for SpecializedFieldElement<S, N>
{
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        Self::new_unchecked(<[u32; N]>::conditional_select(
            a.as_words(),
            b.as_words(),
            c,
        ))
    }
}
impl<S: PrimeFieldSpec<N>, const N: usize> ConstantTimeEq for SpecializedFieldElement<S, N> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.as_words().ct_eq(rhs.as_words())
    }
}
impl<S: PrimeFieldSpec<N>, const N: usize> SecretField for SpecializedFieldElement<S, N> {
    fn ct_zero(&self) -> Self {
        Self::ZERO
    }
    fn ct_one(&self) -> Self {
        Self::ONE
    }
    fn ct_add(&self, rhs: &Self) -> Self {
        Self::new_unchecked(add(self.as_words(), rhs.as_words(), &S::P))
    }
    fn ct_sub(&self, rhs: &Self) -> Self {
        Self::new_unchecked(sub(self.as_words(), rhs.as_words(), &S::P))
    }
    fn ct_mul(&self, rhs: &Self) -> Self {
        Self::new_unchecked(mul(self.as_words(), rhs.as_words(), &S::P))
    }
    fn ct_invert(&self) -> Self {
        Self::new_unchecked(inverse(self.as_words(), &S::P))
    }
}
impl<S: PrimeFieldSpec<N>, const N: usize> SecretCurve for SpecializedCurve<S, N> {
    const BINARY: bool = false;
}

impl ConditionallySelectable for SecP256R1FieldElement {
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        Self(<[u32; 8]>::conditional_select(&a.0, &b.0, c))
    }
}
impl ConstantTimeEq for SecP256R1FieldElement {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.0.ct_eq(&rhs.0)
    }
}
impl SecretField for SecP256R1FieldElement {
    fn ct_zero(&self) -> Self {
        Self::ZERO
    }
    fn ct_one(&self) -> Self {
        Self::ONE
    }
    fn ct_add(&self, rhs: &Self) -> Self {
        Self(add(&self.0, &rhs.0, &SecP256R1Field::P))
    }
    fn ct_sub(&self, rhs: &Self) -> Self {
        Self(sub(&self.0, &rhs.0, &SecP256R1Field::P))
    }
    fn ct_mul(&self, rhs: &Self) -> Self {
        Self(mul(&self.0, &rhs.0, &SecP256R1Field::P))
    }
    fn ct_invert(&self) -> Self {
        Self(inverse(&self.0, &SecP256R1Field::P))
    }
}
impl SecretCurve for SecP256R1Curve {
    const BINARY: bool = false;
}
