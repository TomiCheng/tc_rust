use crate::sect_element::SecTElement;
use crate::{SecTCtCurve, SecTCtPoint, SecTVarCurve, SecTVarPoint};
use core::marker::PhantomData;
use tc_bigint::{ArrayEncoding, PaddedBigUint};

/// The domain parameters of a named curve over the field of `F`, `N` bytes each; the same
/// methods as `tc_f2m_curve_v2`'s `F2mNamedCurve`.
pub struct SecTNamedCurve<F, const N: usize> {
    pub(super) a: [u8; N],
    pub(super) b: [u8; N],
    pub(super) order: [u8; N],
    pub(super) cofactor: u32,
    pub(super) gx: [u8; N],
    pub(super) gy: [u8; N],
    pub(super) field: PhantomData<fn() -> F>,
}

impl<F: SecTElement, const N: usize> SecTNamedCurve<F, N> {
    pub fn ct_curve(&self) -> SecTCtCurve<F> {
        let [a, b] = [&self.a, &self.b].map(|bytes| element(bytes));
        SecTCtCurve::new(a, b, self.order(), PaddedBigUint::from(self.cofactor))
    }

    pub fn var_curve(&self) -> SecTVarCurve<F> {
        let [a, b] = [&self.a, &self.b].map(|bytes| element(bytes));
        SecTVarCurve::new(a, b, self.order(), PaddedBigUint::from(self.cofactor))
    }

    pub fn ct_generator<'a>(&self, curve: &'a SecTCtCurve<F>) -> SecTCtPoint<'a, F> {
        curve
            .create_point(&self.gx, &self.gy)
            .expect("a named generator is reduced")
    }

    pub fn var_generator<'a>(&self, curve: &'a SecTVarCurve<F>) -> SecTVarPoint<'a, F> {
        curve
            .create_point(&self.gx, &self.gy)
            .expect("a named generator is reduced")
    }

    fn order(&self) -> PaddedBigUint {
        let Ok(order) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&self.order);
        order
    }
}

fn element<F: SecTElement>(bytes: &[u8]) -> F {
    F::from_be(bytes).expect("a named curve's parameters are field elements")
}
