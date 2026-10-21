use core::fmt;

use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{
    CoordinateSystem, Curve, Point, PointDecodeError, PrimeFieldElement, glv, wnaf,
};

use crate::{FpError, FpField, FpFieldElement, FpVarPoint, sec1};

pub struct FpVarCurve<'a> {
    field: &'a FpField,
    a: FpFieldElement<'a>,
    b: FpFieldElement<'a>,
    order: Option<PaddedBigUint>,
    cofactor: Option<PaddedBigUint>,
    coordinate_system: CoordinateSystem,
    glv: Option<Glv<'a>>,
}

// BC's `GlvTypeBEndomorphism`: φ(x, y) = (βx, y), and the split of its λ.
struct Glv<'a> {
    beta: FpFieldElement<'a>,
    split: glv::ScalarSplit,
}

impl<'a> FpVarCurve<'a> {
    /// `y² = x³ + ax + b` over `field`, in affine coordinates. Fails when `a` or `b` is not
    /// below `q`.
    pub fn new(
        field: &'a FpField,
        a: &PaddedBigUint,
        b: &PaddedBigUint,
        order: Option<PaddedBigUint>,
        cofactor: Option<PaddedBigUint>,
    ) -> Result<Self, FpError> {
        Ok(Self {
            field,
            a: field.element(a)?,
            b: field.element(b)?,
            order,
            cofactor,
            coordinate_system: CoordinateSystem::Affine,
            glv: None,
        })
    }

    /// The same curve multiplying by BC's GLV split, as BC's `ConfigureCurveGlv` sets it up:
    /// φ(x, y) = (βx, y) for `beta` a cube root of one is multiplication by some λ on the
    /// subgroup of order n, and `split` holds the parameters of that λ. Multiples then hold,
    /// as in BC, only for points of that subgroup. Fails when `beta` is not below `q`; panics
    /// on a curve without an order.
    pub fn with_glv(
        mut self,
        beta: &PaddedBigUint,
        split: glv::ScalarSplit,
    ) -> Result<Self, FpError> {
        assert!(self.order.is_some(), "GLV needs the order");
        self.glv = Some(Glv {
            beta: self.field.element(beta)?,
            split,
        });
        Ok(self)
    }

    /// The same curve with its points in `coordinate_system`. Panics when it is not one
    /// of [`supports_coordinate_system`](Self::supports_coordinate_system).
    pub fn with_coordinate_system(mut self, coordinate_system: CoordinateSystem) -> Self {
        assert!(
            Self::supports_coordinate_system(coordinate_system),
            "unsupported Fp coordinate system"
        );
        self.coordinate_system = coordinate_system;
        self
    }

    /// Affine, homogeneous, Jacobian and modified Jacobian, as in BC.
    pub const fn supports_coordinate_system(coordinate_system: CoordinateSystem) -> bool {
        matches!(
            coordinate_system,
            CoordinateSystem::Affine
                | CoordinateSystem::Homogeneous
                | CoordinateSystem::Jacobian
                | CoordinateSystem::JacobianModified
        )
    }

    pub fn coordinate_system(&self) -> CoordinateSystem {
        self.coordinate_system
    }

    pub fn field(&self) -> &'a FpField {
        self.field
    }

    pub fn a(&self) -> &FpFieldElement<'a> {
        &self.a
    }

    pub fn b(&self) -> &FpFieldElement<'a> {
        &self.b
    }

    pub fn order(&self) -> Option<&PaddedBigUint> {
        self.order.as_ref()
    }

    pub fn cofactor(&self) -> Option<&PaddedBigUint> {
        self.cofactor.as_ref()
    }

    pub fn infinity(&'a self) -> FpVarPoint<'a> {
        FpVarPoint::infinity(self)
    }

    /// The point `(x, y)`, which is not checked against the curve; see [`FpVarPoint::is_valid`].
    /// Fails when a coordinate is not below `q`.
    pub fn create_point(
        &'a self,
        x: &PaddedBigUint,
        y: &PaddedBigUint,
    ) -> Result<FpVarPoint<'a>, FpError> {
        Ok(FpVarPoint::new(
            self,
            self.field.element(x)?,
            self.field.element(y)?,
        ))
    }

    /// The bytes of one coordinate in the SEC 1 encoding.
    pub fn field_element_encoding_length(&self) -> usize {
        sec1::coordinate_length(self.field)
    }

    /// The bytes of the SEC 1 encoding of a finite point.
    pub fn affine_point_encoding_length(&self, compressed: bool) -> usize {
        sec1::point_length(self.field, compressed)
    }

    /// The point with this `x` whose `y` has the parity `y_tilde`, or `None` when there is
    /// none. Variable time; only for public points.
    pub fn decompress_point(&'a self, y_tilde: u8, x: &PaddedBigUint) -> Option<FpVarPoint<'a>> {
        let (x, y) = sec1::decompress(self.field, &self.a, &self.b, y_tilde, x)?;
        Some(FpVarPoint::new(self, x, y))
    }

    /// Decodes the SEC 1 infinity, compressed, uncompressed and hybrid forms, and checks
    /// that the point is on the curve; the subgroup is not checked, as in BC. Variable
    /// time; only for public points.
    pub fn decode_point(&'a self, encoded: &[u8]) -> Result<FpVarPoint<'a>, PointDecodeError> {
        Ok(match sec1::decode(self.field, &self.a, &self.b, encoded)? {
            None => self.infinity(),
            Some((x, y)) => FpVarPoint::new(self, x, y),
        })
    }
}

impl<'a> Curve for &'a FpVarCurve<'a> {
    type Field = FpFieldElement<'a>;
    type Point = FpVarPoint<'a>;
    type Scalar = PaddedBigUint;

    fn a(&self) -> &FpFieldElement<'a> {
        &self.a
    }

    fn b(&self) -> &FpFieldElement<'a> {
        &self.b
    }

    fn order(&self) -> Option<&PaddedBigUint> {
        self.order.as_ref()
    }

    fn cofactor(&self) -> Option<&PaddedBigUint> {
        self.cofactor.as_ref()
    }

    fn zero(&self) -> FpFieldElement<'a> {
        self.field.zero()
    }

    fn one(&self) -> FpFieldElement<'a> {
        self.field.one()
    }

    fn infinity(&self) -> FpVarPoint<'a> {
        FpVarPoint::infinity(self)
    }

    fn create_point(&self, x: FpFieldElement<'a>, y: FpFieldElement<'a>) -> FpVarPoint<'a> {
        FpVarPoint::new(self, x, y)
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        self.coordinate_system
    }

    /// BC's GLV split on a curve given one by [`FpVarCurve::with_glv`], and the wNAF
    /// otherwise. Variable time; only for public scalars.
    fn multiply(point: &FpVarPoint<'a>, scalar: &PaddedBigUint) -> FpVarPoint<'a> {
        match &point.curve().glv {
            Some(params) => glv::glv_mul_point::<Self>(point, scalar, &params.split, |p| {
                p.scale_x(&params.beta)
            }),
            None => wnaf::wnaf_mul_point::<Self>(point, scalar),
        }
    }
}

/// Same field and coefficients, as in BC; the order, cofactor and coordinate system are
/// left out.
impl PartialEq for FpVarCurve<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.a == other.a && self.b == other.b
    }
}

impl Eq for FpVarCurve<'_> {}

impl fmt::Debug for FpVarCurve<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FpVarCurve")
            .field("field", self.field)
            .field("a", &format_args!("{:#x}", self.a.to_big_uint()))
            .field("b", &format_args!("{:#x}", self.b.to_big_uint()))
            .field("coordinate_system", &self.coordinate_system)
            .finish_non_exhaustive()
    }
}
