//! `tc_ec_core` 抽象在泛型 F2m 實作上的具體綁定。
//!
//! F2m 是 core traits 的第二個真實實作：它證實平方根屬於共通體元素、
//! `solve_quadratic` 屬於曲線解壓縮流程，並讓中立的純量乘演算法跨 Fp/F2m
//! 靜態分派。此處不建立 trait object。

use tc_bigint::{BigUint, BitOps};
use tc_ec_core::{BinaryFieldElement, Curve, FieldElement, Point};

use crate::{F2mCurve, F2mFieldElement, F2mPoint, F2mPolynomial};

impl<P: F2mPolynomial> FieldElement for F2mFieldElement<P> {
    fn zero(&self) -> Self {
        F2mFieldElement::zero(self)
    }

    fn one(&self) -> Self {
        F2mFieldElement::one(self)
    }

    fn is_zero(&self) -> bool {
        F2mFieldElement::is_zero(self)
    }

    fn is_one(&self) -> bool {
        F2mFieldElement::is_one(self)
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
        F2mFieldElement::square(self)
    }

    fn sqrt(&self) -> Option<Self> {
        Some(F2mFieldElement::sqrt(self))
    }

    fn negate(&self) -> Self {
        -self
    }

    fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            Some(F2mFieldElement::invert(self))
        }
    }
}

impl<P: F2mPolynomial> BinaryFieldElement for F2mFieldElement<P> {
    fn trace(&self) -> u8 {
        F2mFieldElement::trace(self)
    }

    fn half_trace(&self) -> Self {
        F2mFieldElement::half_trace(self)
    }
}

impl<P: F2mPolynomial> Curve for F2mCurve<P> {
    type Field = F2mFieldElement<P>;
    type Point = F2mPoint<P>;
    type Scalar = BigUint;

    fn a(&self) -> &Self::Field {
        F2mCurve::a(self)
    }

    fn b(&self) -> &Self::Field {
        F2mCurve::b(self)
    }

    fn order(&self) -> Option<&Self::Scalar> {
        F2mCurve::order(self)
    }

    fn cofactor(&self) -> Option<&Self::Scalar> {
        F2mCurve::cofactor(self)
    }

    fn scalar_bit_length(scalar: &Self::Scalar) -> usize {
        scalar.bit_length()
    }

    fn scalar_test_bit(scalar: &Self::Scalar, index: usize) -> bool {
        scalar.test_bit(index)
    }
}

impl<P: F2mPolynomial> Point for F2mPoint<P> {
    type Curve = F2mCurve<P>;

    fn identity(&self) -> Self {
        self.curve().infinity()
    }

    fn is_identity(&self) -> bool {
        F2mPoint::is_infinity(self)
    }

    fn add(&self, rhs: &Self) -> Self {
        self + rhs
    }

    fn double(&self) -> Self {
        F2mPoint::twice(self)
    }

    fn negate(&self) -> Self {
        -self
    }

    fn normalize(&self) -> Self {
        F2mPoint::normalize(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::named_curves::{sect163k1, sect163k1_dynamic, sect233k1, sect233k1_dynamic};
    use tc_binpoly::{BinaryPoly, FixedBinaryPoly};
    use tc_ec_core::scalar_mul;

    fn assert_algorithm<P: F2mPolynomial>(point: F2mPoint<P>, scalar: &BigUint) {
        assert_eq!(
            scalar_mul::<F2mCurve<P>>(&point, scalar),
            point.mul_double_and_add(scalar)
        );
    }

    #[test]
    fn trait_methods_delegate_to_f2m_formulas() {
        let (_, point) = sect163k1();
        let x = point.x().unwrap();
        assert_eq!(FieldElement::square(x), x.square());
        assert_eq!(FieldElement::sqrt(x), Some(x.sqrt()));
        assert_eq!(BinaryFieldElement::trace(x), x.trace());
        assert_eq!(BinaryFieldElement::half_trace(x), x.half_trace());
        assert!(FieldElement::invert(&x.zero()).is_none());
        assert_eq!(Point::double(&point), point.twice());
        assert!(Point::is_identity(&Point::identity(&point)));
    }

    #[test]
    fn neutral_scalar_mul_runs_on_both_curves_and_polynomial_backends() {
        let scalar_163 =
            BigUint::from_str_radix("051F7A94D308C624B1E975A06D42F89C357E1ABCD", 16).unwrap();
        let scalar_233 = BigUint::from_str_radix(
            "01E46A835F1D90C27B469E03A758D124CB6F2809D537E41ACB9865D3F12",
            16,
        )
        .unwrap();

        assert_algorithm::<FixedBinaryPoly<3>>(sect163k1().1, &scalar_163);
        assert_algorithm::<BinaryPoly>(sect163k1_dynamic().1, &scalar_163);
        assert_algorithm::<FixedBinaryPoly<4>>(sect233k1().1, &scalar_233);
        assert_algorithm::<BinaryPoly>(sect233k1_dynamic().1, &scalar_233);
    }
}
