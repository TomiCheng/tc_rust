//! `tc_ec_core` 抽象在泛型 F2m 實作上的具體綁定。
//!
//! F2m 是 core traits 的第二個真實實作：它證實平方根屬於共通體元素、
//! `solve_quadratic` 屬於曲線解壓縮流程，並讓中立的純量乘演算法跨 Fp/F2m
//! 靜態分派。此處不建立 trait object。

use alloc::sync::Arc;

use tc_ec_core::{BinaryFieldElement, Curve, FieldElement, Point};

use crate::{F2mCurve, F2mFieldElement, F2mInteger, F2mPoint, F2mPolynomial};

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

impl<P: F2mPolynomial, B: F2mInteger> Curve for F2mCurve<P, B> {
    type Field = F2mFieldElement<P>;
    type Point = F2mPoint<P, B>;
    type Scalar = B;

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

    fn identity(self: &Arc<Self>) -> Self::Point {
        self.infinity()
    }

    fn create_point(self: &Arc<Self>, x: Self::Field, y: Self::Field) -> Self::Point {
        F2mPoint::new(Arc::clone(self), x, y)
    }

    fn coordinate_system(&self) -> tc_ec_core::CoordinateSystem {
        F2mCurve::coordinate_system(self)
    }

    fn scalar_bit_length(scalar: &Self::Scalar) -> usize {
        scalar.bit_length()
    }

    fn scalar_test_bit(scalar: &Self::Scalar, index: usize) -> bool {
        scalar.test_bit(index)
    }
}

impl<P: F2mPolynomial, B: F2mInteger> Point for F2mPoint<P, B> {
    type Curve = F2mCurve<P, B>;

    fn identity(&self) -> Self {
        self.curve().infinity()
    }

    fn is_identity(&self) -> bool {
        F2mPoint::is_infinity(self)
    }

    fn x(&self) -> Option<<Self::Curve as Curve>::Field> {
        F2mPoint::x(self).cloned()
    }

    fn y(&self) -> Option<<Self::Curve as Curve>::Field> {
        F2mPoint::y(self).cloned()
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
    use crate::named_curves::{hex, sect163k1, sect163k1_dynamic, sect233k1, sect233k1_dynamic};
    use tc_bigint::{BigUint, U256};
    use tc_binpoly::{BinaryPoly, FixedBinaryPoly};
    use tc_ec_core::scalar_mul;

    fn assert_algorithm<P: F2mPolynomial, B: F2mInteger>(point: F2mPoint<P, B>, scalar: &B) {
        assert_eq!(
            scalar_mul::<F2mCurve<P, B>>(&point, scalar),
            point.mul_double_and_add(scalar)
        );
    }

    #[test]
    fn trait_methods_delegate_to_f2m_formulas() {
        let (curve, point) = sect163k1();
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        assert_eq!(FieldElement::square(x), x.square());
        assert_eq!(FieldElement::sqrt(x), Some(x.sqrt()));
        assert_eq!(BinaryFieldElement::trace(x), x.trace());
        assert_eq!(BinaryFieldElement::half_trace(x), x.half_trace());
        assert!(FieldElement::invert(&x.zero()).is_none());
        assert_eq!(Point::x(&point), Some(x.clone()));
        assert_eq!(Point::y(&point), Some(y.clone()));
        assert_eq!(Point::double(&point), point.twice());
        assert!(Point::is_identity(&Point::identity(&point)));
        assert!(Curve::identity(&curve).is_infinity());
        assert_eq!(Curve::create_point(&curve, x.clone(), y.clone()), point);
        assert_eq!(Point::twice_plus(&point, &point), point.three_times());
        assert_eq!(Point::three_times(&point), &point.twice() + &point);
        assert_eq!(Point::times_pow2(&point, 3), point.twice().twice().twice());
        assert_eq!(
            Curve::coordinate_system(curve.as_ref()),
            tc_ec_core::CoordinateSystem::Affine
        );
    }

    #[test]
    fn neutral_scalar_mul_runs_on_both_curves_and_polynomial_backends() {
        let scalar_163_fixed = hex::<U256>("051F7A94D308C624B1E975A06D42F89C357E1ABCD");
        let scalar_163_dynamic = hex::<BigUint>("051F7A94D308C624B1E975A06D42F89C357E1ABCD");
        let scalar_233_fixed =
            hex::<U256>("01E46A835F1D90C27B469E03A758D124CB6F2809D537E41ACB9865D3F12");
        let scalar_233_dynamic =
            hex::<BigUint>("01E46A835F1D90C27B469E03A758D124CB6F2809D537E41ACB9865D3F12");

        assert_algorithm::<FixedBinaryPoly<3>, U256>(sect163k1().1, &scalar_163_fixed);
        assert_algorithm::<BinaryPoly, BigUint>(sect163k1_dynamic().1, &scalar_163_dynamic);
        assert_algorithm::<FixedBinaryPoly<4>, U256>(sect233k1().1, &scalar_233_fixed);
        assert_algorithm::<BinaryPoly, BigUint>(sect233k1_dynamic().1, &scalar_233_dynamic);
    }
}
