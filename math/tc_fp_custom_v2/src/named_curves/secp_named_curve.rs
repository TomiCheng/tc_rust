use crate::secp_element::SecPElement;
use crate::{SecPCtCurve, SecPCtPoint, SecPVarCurve, SecPVarPoint};
use core::marker::PhantomData;

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
        todo!()
    }

    pub fn var_curve(&self) -> SecPVarCurve<F> {
        todo!()
    }

    pub fn ct_generator<'a>(&self, _curve: &'a SecPCtCurve<F>) -> SecPCtPoint<'a, F> {
        todo!()
    }

    pub fn var_generator<'a>(&self, _curve: &'a SecPVarCurve<F>) -> SecPVarPoint<'a, F> {
        todo!()
    }
}
