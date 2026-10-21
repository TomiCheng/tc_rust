use crate::SecTVarPoint;
use crate::sect_element::SecTElement;
use crate::{SecTError, sec1};
use core::fmt;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{CoordinateSystem, Curve, Point, PointDecodeError, tnaf, wnaf};

/// A SEC binary curve over the field of `F`, in lambda-projective coordinates as BC's
/// `SecT*Curve`s are; variable time, only for public values.
pub struct SecTVarCurve<F> {
    a: F,
    b: F,
    order: PaddedBigUint,
    cofactor: PaddedBigUint,
    small_b: bool,
}

impl<F: SecTElement> SecTVarCurve<F> {
    pub(crate) fn new(a: F, b: F, order: PaddedBigUint, cofactor: PaddedBigUint) -> Self {
        let small_b = bit_length(&b) < F::M / 2;
        Self {
            a,
            b,
            order,
            cofactor,
            small_b,
        }
    }

    // Whether b has fewer bits than half the field, which picks BC's doubling formula.
    pub(crate) fn small_b(&self) -> bool {
        self.small_b
    }

    pub fn infinity(&self) -> SecTVarPoint<'_, F> {
        SecTVarPoint::infinity(self)
    }

    /// The point `(x, y)` from SEC 1 octet strings, which is not checked against the curve.
    pub fn create_point(&self, x: &[u8], y: &[u8]) -> Result<SecTVarPoint<'_, F>, SecTError> {
        Ok(SecTVarPoint::new(
            self,
            sec1::element(x)?,
            sec1::element(y)?,
        ))
    }

    /// The bytes of one coordinate in the SEC 1 encoding, `⌈m / 8⌉`.
    pub fn field_element_encoding_length(&self) -> usize {
        sec1::coordinate_length::<F>()
    }

    /// The bytes of the SEC 1 encoding of a finite point.
    pub fn affine_point_encoding_length(&self, compressed: bool) -> usize {
        sec1::point_length::<F>(compressed)
    }

    /// The point with the SEC 1 octet string `x` whose compression bit is `y_tilde`, or
    /// `None` when there is none. Variable time; only for public points.
    pub fn decompress_point(&self, y_tilde: u8, x: &[u8]) -> Option<SecTVarPoint<'_, F>> {
        let (x, y) = sec1::decompress(&self.a, &self.b, y_tilde, x)?;
        Some(SecTVarPoint::new(self, x, y))
    }

    /// Decodes the SEC 1 infinity, compressed, uncompressed and hybrid forms, and checks
    /// that the point is on the curve; the subgroup is not checked, as in BC. An encoding
    /// is public: this is variable time in it, as decompression takes a half-trace.
    pub fn decode_point(&self, encoded: &[u8]) -> Result<SecTVarPoint<'_, F>, PointDecodeError> {
        Ok(match sec1::decode(&self.a, &self.b, encoded)? {
            None => self.infinity(),
            Some((x, y)) => SecTVarPoint::new(self, x, y),
        })
    }
}

fn bit_length<F: SecTElement>(x: &F) -> usize {
    let mut bytes = [0; 72];
    let bytes = &mut bytes[..x.encoded_length()];
    x.encode_to(bytes);
    match bytes.iter().position(|&byte| byte != 0) {
        Some(i) => (bytes.len() - i) * 8 - bytes[i].leading_zeros() as usize,
        None => 0,
    }
}

impl<'a, F: SecTElement> Curve for &'a SecTVarCurve<F> {
    type Field = F;
    type Point = SecTVarPoint<'a, F>;
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

    fn infinity(&self) -> SecTVarPoint<'a, F> {
        SecTVarPoint::infinity(self)
    }

    fn create_point(&self, x: F, y: F) -> SecTVarPoint<'a, F> {
        SecTVarPoint::new(self, x, y)
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        CoordinateSystem::LambdaProjective
    }

    /// The window τ-adic NAF on a Koblitz curve and the wNAF elsewhere, as BC's
    /// `CreateDefaultMultiplier` picks. On a Koblitz curve the result holds, as in BC, only
    /// for points of the subgroup of order n. Variable time; only for public scalars.
    fn multiply(point: &SecTVarPoint<'a, F>, scalar: &PaddedBigUint) -> SecTVarPoint<'a, F> {
        if tnaf::is_koblitz(&point.curve()) {
            tnaf::wtnaf_mul_point::<Self>(point, scalar, F::M as u32, SecTVarPoint::tau)
        } else {
            wnaf::wnaf_mul_point::<Self>(point, scalar)
        }
    }
}

/// The same coefficients, as in BC; the order and cofactor are left out.
impl<F: SecTElement> PartialEq for SecTVarCurve<F> {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}

impl<F: SecTElement> Eq for SecTVarCurve<F> {}

impl<F> fmt::Debug for SecTVarCurve<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecTVarCurve").finish_non_exhaustive()
    }
}
