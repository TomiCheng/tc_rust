use crate::secp_element::SecPElement;
use crate::{SecPCtCurve, SecPCtPoint, SecPVarCurve, SecPVarPoint};
use core::marker::PhantomData;
use tc_bigint::{ArrayEncoding, PaddedBigUint};

/// The domain parameters of a named curve over the field of `F`, `N` bytes each; the same
/// methods as `tc_fp_curve_v2`'s `FpNamedCurve`, without its field.
pub struct SecPNamedCurve<F, const N: usize> {
    pub(super) a: [u8; N],
    pub(super) b: [u8; N],
    pub(super) order: [u8; N],
    pub(super) cofactor: u32,
    pub(super) gx: [u8; N],
    pub(super) gy: [u8; N],
    pub(super) field: PhantomData<fn() -> F>,
}

impl<F: SecPElement, const N: usize> SecPNamedCurve<F, N> {
    pub fn ct_curve(&self) -> SecPCtCurve<F> {
        let [a, b] = [&self.a, &self.b].map(|bytes| element(bytes));
        SecPCtCurve::new(a, b, self.order(), PaddedBigUint::from(self.cofactor))
    }

    pub fn var_curve(&self) -> SecPVarCurve<F> {
        let [a, b] = [&self.a, &self.b].map(|bytes| element(bytes));
        SecPVarCurve::new(a, b, self.order(), PaddedBigUint::from(self.cofactor))
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
