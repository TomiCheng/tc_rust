use crate::secp_element::SecPElement;
use crate::{SecPCtCurve, SecPCtPoint, SecPVarCurve, SecPVarPoint};
use alloc::format;
use core::marker::PhantomData;
use tc_bigint::{ArrayEncoding, BigInt, PaddedBigUint};
use tc_ec_core_v2::glv::ScalarSplit;

/// The domain parameters of a named curve over the field of `F`, `N` bytes each and `O` for
/// the order, which takes a byte more on the 160-bit curves; the same methods as
/// `tc_fp_curve_v2`'s `FpNamedCurve`, without its field.
pub struct SecPNamedCurve<F, const N: usize, const O: usize = N> {
    pub(super) a: [u8; N],
    pub(super) b: [u8; N],
    pub(super) order: [u8; O],
    pub(super) cofactor: u32,
    pub(super) gx: [u8; N],
    pub(super) gy: [u8; N],
    pub(super) glv: Option<NamedGlv>,
    pub(super) field: PhantomData<fn() -> F>,
}

/// BC's `GlvTypeBParameters` of a named curve, as hex: β, and the `ScalarSplitParameters` of
/// its λ.
pub(super) struct NamedGlv {
    pub(super) beta: &'static str,
    pub(super) v1: [&'static str; 2],
    pub(super) v2: [&'static str; 2],
    pub(super) g1: &'static str,
    pub(super) g2: &'static str,
    pub(super) bits: u32,
}

impl NamedGlv {
    fn split(&self) -> ScalarSplit {
        ScalarSplit::new(
            self.v1.map(big_int),
            self.v2.map(big_int),
            big_int(self.g1),
            big_int(self.g2),
            self.bits,
        )
    }
}

// A signed hexadecimal constant.
fn big_int(text: &str) -> BigInt {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, text),
    };
    let value = digits.chars().fold(BigInt::from(0u8), |acc, digit| {
        (acc << 4) + BigInt::from(digit.to_digit(16).expect("a hexadecimal digit"))
    });
    if negative { -value } else { value }
}

impl<F: SecPElement, const N: usize, const O: usize> SecPNamedCurve<F, N, O> {
    pub fn ct_curve(&self) -> SecPCtCurve<F> {
        let [a, b] = [&self.a, &self.b].map(|bytes| element(bytes));
        SecPCtCurve::new(a, b, self.order(), PaddedBigUint::from(self.cofactor))
    }

    pub fn var_curve(&self) -> SecPVarCurve<F> {
        let [a, b] = [&self.a, &self.b].map(|bytes| element(bytes));
        let curve = SecPVarCurve::new(a, b, self.order(), PaddedBigUint::from(self.cofactor));
        match &self.glv {
            Some(glv) => {
                let text = format!("{:0>width$}", glv.beta, width = 2 * N);
                let beta: [u8; N] = core::array::from_fn(|i| {
                    u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hexadecimal")
                });
                curve.with_glv(element(&beta), glv.split())
            }
            None => curve,
        }
    }

    pub fn ct_generator<'a>(&self, curve: &'a SecPCtCurve<F>) -> SecPCtPoint<'a, F> {
        curve
            .create_point(&self.gx, &self.gy)
            .expect("a named generator lies below p")
    }

    pub fn var_generator<'a>(&self, curve: &'a SecPVarCurve<F>) -> SecPVarPoint<'a, F> {
        curve
            .create_point(&self.gx, &self.gy)
            .expect("a named generator lies below p")
    }

    fn order(&self) -> PaddedBigUint {
        let Ok(order) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&self.order);
        order
    }
}

fn element<F: SecPElement>(bytes: &[u8]) -> F {
    F::from_be(bytes).expect("a named curve's parameters lie below p")
}
