use core::fmt;

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{CoordinateSystem, PointDecodeError};

use crate::{FpField, FpFieldElement, FpPoint};

pub struct FpCurve<'a> {
    field: &'a FpField,
    a: FpFieldElement<'a>,
    b: FpFieldElement<'a>,
    order: Option<PaddedBigUint>,
    cofactor: Option<PaddedBigUint>,
    coordinate_system: CoordinateSystem,
}

impl<'a> FpCurve<'a> {
    /// `y² = x³ + ax + b` over `field`, in affine coordinates. Panics when `a` or `b`
    /// is not below `q`.
    pub fn new(
        field: &'a FpField,
        a: &PaddedBigUint,
        b: &PaddedBigUint,
        order: Option<PaddedBigUint>,
        cofactor: Option<PaddedBigUint>,
    ) -> Self {
        Self {
            field,
            a: field.element(a),
            b: field.element(b),
            order,
            cofactor,
            coordinate_system: CoordinateSystem::Affine,
        }
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

    pub fn infinity(&'a self) -> FpPoint<'a> {
        FpPoint::infinity(self)
    }

    /// The point `(x, y)`, which is not checked against the curve; see [`FpPoint::is_valid`].
    /// Panics when a coordinate is not below `q`.
    pub fn create_point(&'a self, x: &PaddedBigUint, y: &PaddedBigUint) -> FpPoint<'a> {
        FpPoint::new(self, self.field.element(x), self.field.element(y))
    }

    /// The bytes of one coordinate in the SEC 1 encoding.
    pub fn field_element_encoding_length(&self) -> usize {
        (self.field.q().bits() as usize).div_ceil(8)
    }

    /// The bytes of the SEC 1 encoding of a finite point.
    pub fn affine_point_encoding_length(&self, compressed: bool) -> usize {
        let len = self.field_element_encoding_length();
        if compressed { 1 + len } else { 1 + 2 * len }
    }

    /// The point with this `x` whose `y` has the parity `y_tilde`, or `None` when there is
    /// none. Variable time; only for public points.
    pub fn decompress_point(&'a self, y_tilde: u8, x: &PaddedBigUint) -> Option<FpPoint<'a>> {
        if y_tilde > 1 || x >= self.field.q() {
            return None;
        }
        let x = self.field.element(x);
        let y = (&(&(&x.square() + &self.a) * &x) + &self.b).sqrt()?;
        let y = if y.to_big_uint().bit(0) == (y_tilde == 1) {
            y
        } else {
            -&y
        };
        Some(FpPoint::new(self, x, y))
    }

    /// Decodes the SEC 1 infinity, compressed, uncompressed and hybrid forms, and checks
    /// that the point is on the curve; the subgroup is not checked, as in BC. Variable
    /// time; only for public points.
    pub fn decode_point(&'a self, encoded: &[u8]) -> Result<FpPoint<'a>, PointDecodeError> {
        let len = self.field_element_encoding_length();
        let (&tag, body) = encoded.split_first().ok_or(PointDecodeError::Empty)?;
        match tag {
            0x00 if body.is_empty() => Ok(self.infinity()),
            0x00 => Err(PointDecodeError::InvalidLength),
            0x02 | 0x03 => {
                if body.len() != len {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = self.decode_coordinate(body)?;
                self.decompress_point(tag & 1, &x)
                    .ok_or(PointDecodeError::NotOnCurve)
            }
            0x04 | 0x06 | 0x07 => {
                if body.len() != 2 * len {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = self.decode_coordinate(&body[..len])?;
                let y = self.decode_coordinate(&body[len..])?;
                if tag != 0x04 && y.bit(0) != (tag == 0x07) {
                    return Err(PointDecodeError::InconsistentHybridY);
                }
                let point = self.create_point(&x, &y);
                if !point.is_on_curve() {
                    return Err(PointDecodeError::NotOnCurve);
                }
                Ok(point)
            }
            other => Err(PointDecodeError::UnknownEncoding(other)),
        }
    }

    fn decode_coordinate(&self, bytes: &[u8]) -> Result<PaddedBigUint, PointDecodeError> {
        let value = <PaddedBigUint as ArrayEncoding<u8>>::from_be(bytes)
            .map_err(|_| PointDecodeError::CoordinateOutOfRange)?;
        if &value >= self.field.q() {
            return Err(PointDecodeError::CoordinateOutOfRange);
        }
        Ok(value)
    }
}

/// Same field and coefficients, as in BC; the order, cofactor and coordinate system are
/// left out.
impl PartialEq for FpCurve<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.a == other.a && self.b == other.b
    }
}

impl Eq for FpCurve<'_> {}

impl fmt::Debug for FpCurve<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FpCurve")
            .field("field", self.field)
            .field("a", &format_args!("{:#x}", self.a.to_big_uint()))
            .field("b", &format_args!("{:#x}", self.b.to_big_uint()))
            .field("coordinate_system", &self.coordinate_system)
            .finish_non_exhaustive()
    }
}
