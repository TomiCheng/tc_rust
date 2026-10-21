use crate::SecPVarPoint;
use crate::secp_element::SecPElement;
use crate::{SecPError, sec1};
use core::fmt;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::glv::ScalarSplit;
use tc_ec_core_v2::{CoordinateSystem, Curve, Point, PointDecodeError, glv, wnaf};

/// A SEC prime curve over the field of `F`, in Jacobian coordinates as BC's `SecP*Curve`s
/// are; variable time, only for public values.
pub struct SecPVarCurve<F> {
    a: F,
    b: F,
    a_is_minus_three: bool,
    order: PaddedBigUint,
    cofactor: PaddedBigUint,
    // BC's `GlvTypeBEndomorphism`: β of φ(x, y) = (βx, y), and the split of its λ.
    glv: Option<(F, ScalarSplit)>,
}

impl<F: SecPElement> SecPVarCurve<F> {
    pub(crate) fn new(a: F, b: F, order: PaddedBigUint, cofactor: PaddedBigUint) -> Self {
        let three = F::one().add(&F::one()).add(&F::one());
        Self {
            a_is_minus_three: a.add(&three).is_zero(),
            a,
            b,
            order,
            cofactor,
            glv: None,
        }
    }

    // BC's `ConfigureCurveGlv`, for the curves whose points are all of order n.
    pub(crate) fn with_glv(mut self, beta: F, split: ScalarSplit) -> Self {
        self.glv = Some((beta, split));
        self
    }

    // Whether a = -3, as on the NIST curves, for the doubling of BC's `SecP*R1Point`.
    pub(crate) fn a_is_minus_three(&self) -> bool {
        self.a_is_minus_three
    }

    pub fn infinity(&self) -> SecPVarPoint<'_, F> {
        SecPVarPoint::infinity(self)
    }

    /// The point `(x, y)` from SEC 1 octet strings, which is not checked against the curve.
    pub fn create_point(&self, x: &[u8], y: &[u8]) -> Result<SecPVarPoint<'_, F>, SecPError> {
        Ok(SecPVarPoint::new(
            self,
            sec1::element(x)?,
            sec1::element(y)?,
        ))
    }

    /// The bytes of one coordinate in the SEC 1 encoding.
    pub fn field_element_encoding_length(&self) -> usize {
        sec1::coordinate_length::<F>()
    }

    /// The bytes of the SEC 1 encoding of a finite point.
    pub fn affine_point_encoding_length(&self, compressed: bool) -> usize {
        sec1::point_length::<F>(compressed)
    }

    /// The point with this `x` whose y has the low bit `y_tilde`, or `None` when there is
    /// none.
    pub fn decompress_point(&self, y_tilde: u8, x: &[u8]) -> Option<SecPVarPoint<'_, F>> {
        let (x, y) = sec1::decompress(&self.a, &self.b, y_tilde, x)?;
        Some(SecPVarPoint::new(self, x, y))
    }

    /// Decodes the SEC 1 infinity, compressed, uncompressed and hybrid forms, and checks
    /// that the point is on the curve; the subgroup is not checked, as in BC.
    pub fn decode_point(&self, encoded: &[u8]) -> Result<SecPVarPoint<'_, F>, PointDecodeError> {
        Ok(match sec1::decode(&self.a, &self.b, encoded)? {
            None => self.infinity(),
            Some((x, y)) => SecPVarPoint::new(self, x, y),
        })
    }
}

impl<'a, F: SecPElement> Curve for &'a SecPVarCurve<F> {
    type Field = F;
    type Point = SecPVarPoint<'a, F>;
    type Scalar = PaddedBigUint;

    fn a(&self) -> &F {
        &self.a
    }

    fn b(&self) -> &F {
        &self.b
    }

    fn order(&self) -> Option<&PaddedBigUint> {
        Some(&self.order)
    }

    fn cofactor(&self) -> Option<&PaddedBigUint> {
        Some(&self.cofactor)
    }

    fn zero(&self) -> F {
        F::zero()
    }

    fn one(&self) -> F {
        F::one()
    }

    fn infinity(&self) -> SecPVarPoint<'a, F> {
        SecPVarPoint::infinity(self)
    }

    fn create_point(&self, x: F, y: F) -> SecPVarPoint<'a, F> {
        SecPVarPoint::new(self, x, y)
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        CoordinateSystem::Jacobian
    }

    /// BC's GLV split on the k1 curves, as BC's `CustomNamedCurves` configures them, and the
    /// core's wNAF otherwise. Variable time; only for a public scalar.
    fn multiply(point: &SecPVarPoint<'a, F>, scalar: &PaddedBigUint) -> SecPVarPoint<'a, F> {
        match &point.curve().glv {
            Some((beta, split)) => {
                glv::glv_mul_point::<Self>(point, scalar, split, |p| p.scale_x(beta))
            }
            None => wnaf::wnaf_mul_point::<Self>(point, scalar),
        }
    }
}

/// The same coefficients, as in BC; the order and cofactor are left out.
impl<F: SecPElement> PartialEq for SecPVarCurve<F> {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}

impl<F: SecPElement> Eq for SecPVarCurve<F> {}

impl<F> fmt::Debug for SecPVarCurve<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecPVarCurve").finish_non_exhaustive()
    }
}
