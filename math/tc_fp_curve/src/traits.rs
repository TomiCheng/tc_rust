//! `tc_ec_core` 抽象在通用 Fp 實作上的具體綁定。
//!
//! 實作只做靜態分派，不建立 trait object。關聯型別同時允許未來的
//! `SecP256R1FieldElement`／`SecP256R1Point` 直接成為另一組曲線實作，而不必
//! 假裝所有曲線都共用目前的動態 `BigUint` 表示。

use tc_bigint::BigUint;
use tc_ec_core::{Curve, FieldElement, Point, PrimeFieldElement};

use crate::{FpCurve, FpFieldElement, FpPoint};

impl FieldElement for FpFieldElement {
    fn zero(&self) -> Self {
        FpFieldElement::zero(self)
    }

    fn one(&self) -> Self {
        FpFieldElement::one(self)
    }

    fn is_zero(&self) -> bool {
        FpFieldElement::is_zero(self)
    }

    fn is_one(&self) -> bool {
        FpFieldElement::is_one(self)
    }

    fn add(&self, rhs: &Self) -> Self {
        self + rhs
    }

    fn sub(&self, rhs: &Self) -> Self {
        self - rhs
    }

    fn mul(&self, rhs: &Self) -> Self {
        self * rhs
    }

    fn square(&self) -> Self {
        FpFieldElement::square(self)
    }

    fn negate(&self) -> Self {
        -self
    }

    fn invert(&self) -> Option<Self> {
        FpFieldElement::invert(self)
    }
}

impl PrimeFieldElement for FpFieldElement {
    type BigUint = BigUint;

    fn sqrt(&self) -> Option<Self> {
        FpFieldElement::sqrt(self)
    }

    fn element_from_big_uint(&self, value: &Self::BigUint) -> Self {
        FpFieldElement::element_from_big_uint(self, value)
    }

    fn to_big_uint(&self) -> Self::BigUint {
        FpFieldElement::to_big_uint(self)
    }
}

impl Curve for FpCurve {
    type Field = FpFieldElement;
    type Point = FpPoint;
    type Scalar = BigUint;

    fn a(&self) -> &Self::Field {
        FpCurve::a(self)
    }

    fn b(&self) -> &Self::Field {
        FpCurve::b(self)
    }

    fn order(&self) -> Option<&Self::Scalar> {
        FpCurve::order(self)
    }

    fn cofactor(&self) -> Option<&Self::Scalar> {
        FpCurve::cofactor(self)
    }
}

impl Point for FpPoint {
    type Curve = FpCurve;

    fn identity(&self) -> Self {
        self.curve().infinity()
    }

    fn is_identity(&self) -> bool {
        FpPoint::is_infinity(self)
    }

    fn add(&self, rhs: &Self) -> Self {
        self + rhs
    }

    fn double(&self) -> Self {
        FpPoint::twice(self)
    }

    fn negate(&self) -> Self {
        -self
    }

    fn normalize(&self) -> Self {
        FpPoint::normalize(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::named_curves::secp256k1;

    #[test]
    fn trait_methods_delegate_to_the_concrete_implementation() {
        let (curve, point) = secp256k1();
        assert_eq!(Curve::a(curve.as_ref()), curve.a());
        assert_eq!(Point::double(&point), point.twice());
        assert_eq!(Point::add(&point, &point), point.twice());
        assert!(Point::is_identity(&Point::identity(&point)));

        let x = point.x().unwrap();
        assert_eq!(FieldElement::square(x), x.square());
        assert_eq!(PrimeFieldElement::to_big_uint(x), x.to_big_uint());
    }
}
