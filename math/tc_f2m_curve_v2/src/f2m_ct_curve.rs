use crate::{F2mCtPoint, F2mError, F2mField, F2mFieldElement};
use core::fmt;
use tc_bigint::PaddedBigUint;

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
