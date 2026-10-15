use tc_bigint::{ArrayEncoding, PaddedBigUint};

use crate::{FpCtCurve, FpCtPoint, FpField, FpVarCurve, FpVarPoint};

/// The domain parameters of a named curve, as BC's `X9ECParameters` holds them.
///
/// A curve borrows its field, so the caller owns the field:
///
/// ```
/// use tc_ec_core_v2::Point;
/// use tc_fp_curve_v2::named_curves::SECP256R1;
///
/// let field = SECP256R1.field();
/// let curve = SECP256R1.ct_curve(&field);
/// let g = SECP256R1.ct_generator(&curve);
/// let public_key = g.multiply(&private_key());
/// # fn private_key() -> tc_bigint::PaddedBigUint { tc_bigint::PaddedBigUint::from(7u8) }
/// assert!(public_key.is_valid());
/// ```
pub struct FpNamedCurve<const N: usize> {
    pub(super) p: [u8; N],
    pub(super) a: [u8; N],
    pub(super) b: [u8; N],
    pub(super) order: [u8; N],
    pub(super) cofactor: u32,
    pub(super) gx: [u8; N],
    pub(super) gy: [u8; N],
}

impl<const N: usize> FpNamedCurve<N> {
    pub fn field(&self) -> FpField {
        FpField::new(int(&self.p)).expect("a named curve has an odd prime")
    }

    pub fn ct_curve<'a>(&self, field: &'a FpField) -> FpCtCurve<'a> {
        FpCtCurve::new(
            field,
            &int(&self.a),
            &int(&self.b),
            Some(int(&self.order)),
            Some(PaddedBigUint::from(self.cofactor)),
        )
        .expect("named-curve coefficients lie below q")
    }

    pub fn var_curve<'a>(&self, field: &'a FpField) -> FpVarCurve<'a> {
        FpVarCurve::new(
            field,
            &int(&self.a),
            &int(&self.b),
            Some(int(&self.order)),
            Some(PaddedBigUint::from(self.cofactor)),
        )
        .expect("named-curve coefficients lie below q")
    }

    pub fn ct_generator<'a>(&self, curve: &'a FpCtCurve<'a>) -> FpCtPoint<'a> {
        curve
            .create_point(&int(&self.gx), &int(&self.gy))
            .expect("a named generator lies below q")
    }

    pub fn var_generator<'a>(&self, curve: &'a FpVarCurve<'a>) -> FpVarPoint<'a> {
        curve
            .create_point(&int(&self.gx), &int(&self.gy))
            .expect("a named generator lies below q")
    }
}

pub(super) fn int(bytes: &[u8]) -> PaddedBigUint {
    <PaddedBigUint as ArrayEncoding<u8>>::from_be(bytes).expect("a named-curve constant decodes")
}
