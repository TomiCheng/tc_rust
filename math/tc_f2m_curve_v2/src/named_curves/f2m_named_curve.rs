use crate::{F2mCtCurve, F2mCtPoint, F2mField, F2mVarCurve, F2mVarPoint};
use tc_bigint::{ArrayEncoding, PaddedBigUint};

/// The domain parameters of a named curve, as BC's `X9ECParameters` holds them.
///
/// ```
/// use tc_ec_core_v2::Point;
/// use tc_f2m_curve_v2::named_curves::SECT283K1;
///
/// let curve = SECT283K1.ct_curve();
/// let g = SECT283K1.ct_generator(&curve);
/// let public_key = g.multiply(&private_key());
/// # fn private_key() -> tc_bigint::PaddedBigUint { tc_bigint::PaddedBigUint::from(7u8) }
/// assert!(public_key.is_valid());
/// ```
pub struct F2mNamedCurve<const N: usize> {
    pub(super) m: u32,
    pub(super) taps: Taps,
    pub(super) a: [u8; N],
    pub(super) b: [u8; N],
    pub(super) order: [u8; N],
    pub(super) cofactor: u32,
    pub(super) gx: [u8; N],
    pub(super) gy: [u8; N],
}

/// The exponents of the reduction polynomial between `x^m` and `1`.
pub(super) enum Taps {
    Trinomial(u32),
    Pentanomial(u32, u32, u32),
}

impl<const N: usize> F2mNamedCurve<N> {
    pub fn field(&self) -> F2mField {
        match self.taps {
            Taps::Trinomial(k) => F2mField::trinomial(self.m, k),
            Taps::Pentanomial(k1, k2, k3) => F2mField::pentanomial(self.m, k1, k2, k3),
        }
        .expect("a named curve has a valid reduction polynomial")
    }

    pub fn ct_curve(&self) -> F2mCtCurve {
        F2mCtCurve::new(
            self.field(),
            &self.a,
            &self.b,
            Some(int(&self.order)),
            Some(PaddedBigUint::from(self.cofactor)),
        )
        .expect("named-curve coefficients are reduced")
    }

    /// In affine coordinates; see [`F2mVarCurve::with_coordinate_system`].
    pub fn var_curve(&self) -> F2mVarCurve {
        F2mVarCurve::new(
            self.field(),
            &self.a,
            &self.b,
            Some(int(&self.order)),
            Some(PaddedBigUint::from(self.cofactor)),
        )
        .expect("named-curve coefficients are reduced")
    }

    pub fn ct_generator<'a>(&self, curve: &'a F2mCtCurve) -> F2mCtPoint<'a> {
        curve
            .create_point(&self.gx, &self.gy)
            .expect("a named generator is reduced")
    }

    pub fn var_generator<'a>(&self, curve: &'a F2mVarCurve) -> F2mVarPoint<'a> {
        curve
            .create_point(&self.gx, &self.gy)
            .expect("a named generator is reduced")
    }
}

fn int(bytes: &[u8]) -> PaddedBigUint {
    <PaddedBigUint as ArrayEncoding<u8>>::from_be(bytes).expect("a named-curve constant decodes")
}
