use core::fmt;

use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{ConstantTime, CoordinateSystem, Curve, FieldElement, PointDecodeError};

use crate::{FpCtPoint, FpField, FpFieldElement, scalar, sec1};

/// `y² = x³ + ax + b` over a prime field, whose points take only constant-time
/// formulas: the complete formulas of Renes, Costello and Batina (2016) in homogeneous
/// coordinates. They are complete when the group has odd order, as it has on every
/// prime-order curve.
pub struct FpCtCurve<'a> {
    field: &'a FpField,
    a: FpFieldElement<'a>,
    b: FpFieldElement<'a>,
    b3: FpFieldElement<'a>,
    order: Option<PaddedBigUint>,
    cofactor: Option<PaddedBigUint>,
}

impl<'a> FpCtCurve<'a> {
    /// The curve over `field`. Panics when `a` or `b` is not below `q`.
    pub fn new(
        field: &'a FpField,
        a: &PaddedBigUint,
        b: &PaddedBigUint,
        order: Option<PaddedBigUint>,
        cofactor: Option<PaddedBigUint>,
    ) -> Self {
        let b = field.element(b);
        Self {
            field,
            a: field.element(a),
            b3: b.double().add(&b),
            b,
            order,
            cofactor,
        }
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

    pub(crate) fn b3(&self) -> &FpFieldElement<'a> {
        &self.b3
    }

    pub fn order(&self) -> Option<&PaddedBigUint> {
        self.order.as_ref()
    }

    pub fn cofactor(&self) -> Option<&PaddedBigUint> {
        self.cofactor.as_ref()
    }

    pub fn infinity(&'a self) -> FpCtPoint<'a> {
        FpCtPoint::infinity(self)
    }

    /// The point `(x, y)`, which is not checked against the curve; see [`FpCtPoint::is_valid`].
    /// Panics when a coordinate is not below `q`.
    pub fn create_point(&'a self, x: &PaddedBigUint, y: &PaddedBigUint) -> FpCtPoint<'a> {
        FpCtPoint::new(self, self.field.element(x), self.field.element(y))
    }

    /// The bytes of one coordinate in the SEC 1 encoding.
    pub fn field_element_encoding_length(&self) -> usize {
        sec1::coordinate_length(self.field)
    }

    /// The bytes of the SEC 1 encoding of a finite point.
    pub fn affine_point_encoding_length(&self, compressed: bool) -> usize {
        sec1::point_length(self.field, compressed)
    }

    /// Decodes the SEC 1 infinity, compressed, uncompressed and hybrid forms, and checks
    /// that the point is on the curve; the subgroup is not checked, as in BC. An encoding
    /// is public: this is variable time in it, as decompression takes a square root.
    pub fn decode_point(&'a self, encoded: &[u8]) -> Result<FpCtPoint<'a>, PointDecodeError> {
        Ok(match sec1::decode(self.field, &self.a, &self.b, encoded)? {
            None => self.infinity(),
            Some((x, y)) => FpCtPoint::new(self, x, y),
        })
    }
}

impl<'a> Curve for &'a FpCtCurve<'a> {
    type Field = FpFieldElement<'a>;
    type Point = FpCtPoint<'a>;
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

    fn infinity(&self) -> FpCtPoint<'a> {
        FpCtPoint::infinity(self)
    }

    fn create_point(&self, x: FpFieldElement<'a>, y: FpFieldElement<'a>) -> FpCtPoint<'a> {
        FpCtPoint::new(self, x, y)
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        CoordinateSystem::Homogeneous
    }

    fn scalar_bit_length(scalar: &PaddedBigUint) -> usize {
        scalar::bit_length(scalar)
    }

    fn scalar_test_bit(scalar: &PaddedBigUint, index: usize) -> bool {
        scalar::test_bit(scalar, index)
    }

    fn scalar_is_zero(scalar: &PaddedBigUint) -> bool {
        scalar::is_zero(scalar)
    }

    fn scalar_shr1(scalar: &PaddedBigUint) -> PaddedBigUint {
        scalar::shr(scalar, 1)
    }

    fn scalar_shr(scalar: &PaddedBigUint, count: usize) -> PaddedBigUint {
        scalar::shr(scalar, count)
    }

    fn scalar_low_bits(scalar: &PaddedBigUint, width: usize) -> u32 {
        scalar::low_bits(scalar, width)
    }

    fn scalar_sub_digit(scalar: &PaddedBigUint, digit: i32) -> PaddedBigUint {
        scalar::sub_digit(scalar, digit)
    }

    /// The fixed-window multiplication of [`FpCtPoint::multiply`]. Constant time.
    fn multiply(point: &FpCtPoint<'a>, scalar: &PaddedBigUint) -> FpCtPoint<'a> {
        point.multiply(scalar)
    }
}

/// Every operation on the curve and its points is constant time.
impl<'a> ConstantTime for &'a FpCtCurve<'a> {}

/// Same field and coefficients, as in BC; the order and cofactor are left out.
impl PartialEq for FpCtCurve<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.a == other.a && self.b == other.b
    }
}

impl Eq for FpCtCurve<'_> {}

impl fmt::Debug for FpCtCurve<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FpCtCurve")
            .field("field", self.field)
            .field("a", &format_args!("{:#x}", self.a.to_big_uint()))
            .field("b", &format_args!("{:#x}", self.b.to_big_uint()))
            .finish_non_exhaustive()
    }
}
