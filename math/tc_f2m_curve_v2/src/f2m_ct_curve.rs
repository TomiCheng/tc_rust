use crate::{F2mCtPoint, F2mError, F2mField, F2mFieldElement, sec1};
use core::fmt;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{CoordinateSystem, Curve, PointDecodeError};

/// `y² + xy = x³ + ax² + b` over a binary field, whose scalar multiplication is a
/// constant-time Montgomery ladder. The other group operations have no complete formulas
/// on binary curves and are variable time, for public points such as in verification.
pub struct F2mCtCurve {
    field: F2mField,
    a: F2mFieldElement,
    b: F2mFieldElement,
    order: Option<PaddedBigUint>,
    cofactor: Option<PaddedBigUint>,
}

impl F2mCtCurve {
    /// The curve over `field`, with `a` and `b` as SEC 1 octet strings. Fails when one is
    /// not `⌈m / 8⌉` bytes or not reduced.
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
        })
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

    pub fn infinity(&self) -> F2mCtPoint<'_> {
        F2mCtPoint::infinity(self)
    }

    /// The point `(x, y)` from SEC 1 octet strings, which is not checked against the curve.
    pub fn create_point(&self, x: &[u8], y: &[u8]) -> Result<F2mCtPoint<'_>, F2mError> {
        Ok(F2mCtPoint::new(
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

    /// Decodes the SEC 1 infinity, compressed, uncompressed and hybrid forms, and checks
    /// that the point is on the curve; the subgroup is not checked, as in BC. An encoding
    /// is public: this is variable time in it, as decompression takes a half-trace.
    pub fn decode_point(&self, encoded: &[u8]) -> Result<F2mCtPoint<'_>, PointDecodeError> {
        Ok(
            match sec1::decode(&self.field, &self.a, &self.b, encoded)? {
                None => self.infinity(),
                Some((x, y)) => F2mCtPoint::new(self, x, y),
            },
        )
    }
}

impl<'a> Curve for &'a F2mCtCurve {
    type Field = F2mFieldElement;
    type Point = F2mCtPoint<'a>;
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

    fn infinity(&self) -> F2mCtPoint<'a> {
        F2mCtPoint::infinity(self)
    }

    fn create_point(&self, x: F2mFieldElement, y: F2mFieldElement) -> F2mCtPoint<'a> {
        F2mCtPoint::new(self, x, y)
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        CoordinateSystem::Affine
    }

    /// The Montgomery ladder of [`F2mCtPoint::multiply`]. Constant time.
    fn multiply(point: &F2mCtPoint<'a>, scalar: &PaddedBigUint) -> F2mCtPoint<'a> {
        point.multiply(scalar)
    }
}

/// Same field and coefficients, as in BC; the order and cofactor are left out.
impl PartialEq for F2mCtCurve {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.a == other.a && self.b == other.b
    }
}

impl Eq for F2mCtCurve {}

impl fmt::Debug for F2mCtCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("F2mCtCurve")
            .field("field", &self.field)
            .finish_non_exhaustive()
    }
}
