use crate::sect_element::SecTElement;
use crate::{SecTCtCurve, SecTCtPoint, SecTVarCurve, SecTVarPoint};
use core::marker::PhantomData;

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
        todo!()
    }

    pub fn var_curve(&self) -> SecTVarCurve<F> {
        todo!()
    }

    pub fn ct_generator<'a>(&self, _curve: &'a SecTCtCurve<F>) -> SecTCtPoint<'a, F> {
        todo!()
    }

    pub fn var_generator<'a>(&self, _curve: &'a SecTVarCurve<F>) -> SecTVarPoint<'a, F> {
        todo!()
    }
}
