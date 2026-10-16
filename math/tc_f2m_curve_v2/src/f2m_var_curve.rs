use crate::{F2mError, F2mField, F2mFieldElement, F2mVarPoint, sec1};
use core::fmt;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{CoordinateSystem, Curve, PointDecodeError};

pub struct F2mVarCurve {
    field: F2mField,
    a: F2mFieldElement,
    b: F2mFieldElement,
    order: Option<PaddedBigUint>,
    cofactor: Option<PaddedBigUint>,
    coordinate_system: CoordinateSystem,
}

impl F2mVarCurve {
    /// `y² + xy = x³ + ax² + b` over `field`, in affine coordinates, with `a` and `b` as
    /// SEC 1 octet strings. Fails when one is not `⌈m / 8⌉` bytes or not reduced.
    pub fn new(
        field: F2mField,
        a: &[u8],
        b: &[u8],
        order: Option<PaddedBigUint>,
        cofactor: Option<PaddedBigUint>,
    ) -> Result<Self, F2mError> {
        Ok(Self {
            a: field.element(a)?,
            b: field.element(b)?,
            field,
            order,
            cofactor,
            coordinate_system: CoordinateSystem::Affine,
        })
    }

    /// The same curve with its points in `coordinate_system`. Panics when it is not one
    /// of [`supports_coordinate_system`](Self::supports_coordinate_system).
    pub fn with_coordinate_system(mut self, coordinate_system: CoordinateSystem) -> Self {
        assert!(
            Self::supports_coordinate_system(coordinate_system),
            "unsupported F2m coordinate system"
        );
        self.coordinate_system = coordinate_system;
        self
    }

    /// Affine, homogeneous and lambda-projective, BC's default, as BC's `F2mCurve` supports.
    pub const fn supports_coordinate_system(coordinate_system: CoordinateSystem) -> bool {
        matches!(
            coordinate_system,
            CoordinateSystem::Affine
                | CoordinateSystem::Homogeneous
                | CoordinateSystem::LambdaProjective
        )
    }

    pub fn coordinate_system(&self) -> CoordinateSystem {
        self.coordinate_system
    }

    pub fn field(&self) -> &F2mField {
        &self.field
    }

    pub fn a(&self) -> &F2mFieldElement {
        &self.a
    }

    pub fn b(&self) -> &F2mFieldElement {
        &self.b
    }

    pub fn order(&self) -> Option<&PaddedBigUint> {
        self.order.as_ref()
    }

    pub fn cofactor(&self) -> Option<&PaddedBigUint> {
        self.cofactor.as_ref()
    }

    pub fn infinity(&self) -> F2mVarPoint<'_> {
        F2mVarPoint::infinity(self)
    }

    /// The point `(x, y)` from SEC 1 octet strings, which is not checked against the curve;
    /// see [`F2mVarPoint::is_on_curve`].
    pub fn create_point(&self, x: &[u8], y: &[u8]) -> Result<F2mVarPoint<'_>, F2mError> {
        Ok(F2mVarPoint::new(
            self,
            self.field.element(x)?,
            self.field.element(y)?,
        ))
    }

    /// The bytes of one coordinate in the SEC 1 encoding, `⌈m / 8⌉`.
    pub fn field_element_encoding_length(&self) -> usize {
        sec1::coordinate_length(&self.field)
    }

    /// The bytes of the SEC 1 encoding of a finite point.
    pub fn affine_point_encoding_length(&self, compressed: bool) -> usize {
        sec1::point_length(&self.field, compressed)
    }

    /// The point with the SEC 1 octet string `x` whose compression bit is `y_tilde`, or
    /// `None` when there is none. Variable time; only for public points.
    pub fn decompress_point(&self, y_tilde: u8, x: &[u8]) -> Option<F2mVarPoint<'_>> {
        let (x, y) = sec1::decompress(&self.field, &self.a, &self.b, y_tilde, x)?;
        Some(F2mVarPoint::new(self, x, y))
    }

    /// Decodes the SEC 1 infinity, compressed, uncompressed and hybrid forms, and checks
    /// that the point is on the curve; the subgroup is not checked, as in BC. Variable
    /// time; only for public points.
    pub fn decode_point(&self, encoded: &[u8]) -> Result<F2mVarPoint<'_>, PointDecodeError> {
        Ok(
            match sec1::decode(&self.field, &self.a, &self.b, encoded)? {
                None => self.infinity(),
                Some((x, y)) => F2mVarPoint::new(self, x, y),
            },
        )
    }
}

impl<'a> Curve for &'a F2mVarCurve {
    type Field = F2mFieldElement;
    type Point = F2mVarPoint<'a>;
    type Scalar = PaddedBigUint;

    fn a(&self) -> &F2mFieldElement {
        &self.a
    }

    fn b(&self) -> &F2mFieldElement {
        &self.b
    }

    fn order(&self) -> Option<&PaddedBigUint> {
        self.order.as_ref()
    }

    fn cofactor(&self) -> Option<&PaddedBigUint> {
        self.cofactor.as_ref()
    }

    fn zero(&self) -> F2mFieldElement {
        self.field.zero()
    }

    fn one(&self) -> F2mFieldElement {
        self.field.one()
    }

    fn infinity(&self) -> F2mVarPoint<'a> {
        F2mVarPoint::infinity(self)
    }

    fn create_point(&self, x: F2mFieldElement, y: F2mFieldElement) -> F2mVarPoint<'a> {
        F2mVarPoint::new(self, x, y)
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        self.coordinate_system
    }

    /// wNAF. Variable time; only for public scalars.
    fn multiply(point: &F2mVarPoint<'a>, scalar: &PaddedBigUint) -> F2mVarPoint<'a> {
        tc_ec_core_v2::wnaf::wnaf_mul_point::<Self>(point, scalar)
    }
}

/// Same field and coefficients, as in BC; the order, cofactor and coordinate system are
/// left out.
impl PartialEq for F2mVarCurve {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.a == other.a && self.b == other.b
    }
}

impl Eq for F2mVarCurve {}

impl fmt::Debug for F2mVarCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("F2mVarCurve")
            .field("field", &self.field)
            .field("coordinate_system", &self.coordinate_system)
            .finish_non_exhaustive()
    }
}
