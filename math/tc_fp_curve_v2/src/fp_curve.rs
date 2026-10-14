use core::fmt;

use tc_bigint::PaddedBigUint;

use crate::{FpField, FpFieldElement, FpPoint};

pub struct FpCurve<'a> {
    field: &'a FpField,
    a: FpFieldElement<'a>,
    b: FpFieldElement<'a>,
    order: Option<PaddedBigUint>,
    cofactor: Option<PaddedBigUint>,
}

impl<'a> FpCurve<'a> {
    /// `y² = x³ + ax + b` over `field`. Panics when `a` or `b` is not below `q`.
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

    pub fn order(&self) -> Option<&PaddedBigUint> {
        self.order.as_ref()
    }

    pub fn cofactor(&self) -> Option<&PaddedBigUint> {
        self.cofactor.as_ref()
    }

    pub fn infinity(&'a self) -> FpPoint<'a> {
        FpPoint::infinity(self)
    }

    /// The point `(x, y)`, which is not checked against the curve; see [`FpPoint::is_on_curve`].
    /// Panics when a coordinate is not below `q`.
    pub fn create_point(&'a self, x: &PaddedBigUint, y: &PaddedBigUint) -> FpPoint<'a> {
        FpPoint::new(self, self.field.element(x), self.field.element(y))
    }
}

/// Same field and coefficients, as in BC; the order and cofactor are left out.
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
            .finish_non_exhaustive()
    }
}
