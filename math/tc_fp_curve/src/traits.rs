//! `tc_ec_core` 抽象在通用 Fp 實作上的具體綁定。
//!
//! 實作只做靜態分派，不建立 trait object。關聯型別同時允許未來的
//! `SecP256R1FieldElement`／`SecP256R1Point` 直接成為另一組曲線實作，而不必
//! 假裝所有曲線都共用目前的動態 `BigUint` 表示。

use alloc::sync::Arc;

use tc_ec_core::{Curve, FieldElement, Point, PrimeFieldElement};

use crate::{FpCurve, FpFieldElement, FpInteger, FpPoint};

impl<B: FpInteger> FieldElement for FpFieldElement<B> {
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

    fn sqrt(&self) -> Option<Self> {
        FpFieldElement::sqrt(self)
    }

    fn negate(&self) -> Self {
        -self
    }

    fn invert(&self) -> Option<Self> {
        FpFieldElement::invert(self)
    }
}

impl<B: FpInteger> PrimeFieldElement for FpFieldElement<B> {
    type BigUint = B;

    fn element_from_big_uint(&self, value: &Self::BigUint) -> Self {
        FpFieldElement::element_from_big_uint(self, value)
    }

    fn to_big_uint(&self) -> Self::BigUint {
        FpFieldElement::to_big_uint(self)
    }
}

impl<B: FpInteger> Curve for FpCurve<B> {
    type Field = FpFieldElement<B>;
    type Point = FpPoint<B>;
    type Scalar = B;

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

    fn identity(self: &Arc<Self>) -> Self::Point {
        self.infinity()
    }

    fn create_point(self: &Arc<Self>, x: Self::Field, y: Self::Field) -> Self::Point {
        FpPoint::new(Arc::clone(self), x, y)
    }

    fn coordinate_system(&self) -> tc_ec_core::CoordinateSystem {
        FpCurve::coordinate_system(self)
    }

    fn scalar_bit_length(scalar: &Self::Scalar) -> usize {
        scalar.bit_length()
    }

    fn scalar_test_bit(scalar: &Self::Scalar, index: usize) -> bool {
        scalar.test_bit(index)
    }
}

impl<B: FpInteger> Point for FpPoint<B> {
    type Curve = FpCurve<B>;

    fn identity(&self) -> Self {
        self.curve().infinity()
    }

    fn is_identity(&self) -> bool {
        FpPoint::is_infinity(self)
    }

    fn x(&self) -> Option<<Self::Curve as Curve>::Field> {
        FpPoint::x(self)
    }

    fn y(&self) -> Option<<Self::Curve as Curve>::Field> {
        FpPoint::y(self)
    }

    fn add(&self, rhs: &Self) -> Self {
        self + rhs
    }

    fn double(&self) -> Self {
        FpPoint::twice(self)
    }

    fn twice_plus(&self, rhs: &Self) -> Self {
        FpPoint::twice_plus(self, rhs)
    }

    fn three_times(&self) -> Self {
        FpPoint::three_times(self)
    }

    fn times_pow2(&self, exponent: usize) -> Self {
        FpPoint::times_pow2(self, exponent)
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
    use crate::named_curves::{secp256k1, secp256k1_dynamic, secp256r1, secp256r1_dynamic};
    use crate::{FpInteger, FpPoint, scalar_mul};
    use tc_bigint::{BigUint, U256};

    #[test]
    fn trait_methods_delegate_to_the_concrete_implementation() {
        let (curve, point) = secp256k1();
        assert_eq!(Curve::a(curve.as_ref()), curve.a());
        assert_eq!(
            Curve::coordinate_system(curve.as_ref()),
            tc_ec_core::CoordinateSystem::Affine
        );
        assert!(Curve::identity(&curve).is_infinity());
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        assert_eq!(Curve::create_point(&curve, x.clone(), y), point);
        assert_eq!(Point::x(&point), Some(x.clone()));
        assert_eq!(Point::double(&point), point.twice());
        assert_eq!(Point::add(&point, &point), point.twice());
        assert_eq!(Point::twice_plus(&point, &point), point.three_times());
        assert_eq!(Point::three_times(&point), &point.twice() + &point);
        assert_eq!(Point::times_pow2(&point, 3), point.times_pow2(3));
        assert!(Point::is_identity(&Point::identity(&point)));

        assert_eq!(FieldElement::square(&x), x.square());
        assert_eq!(FieldElement::sqrt(&x), x.sqrt());
        assert_eq!(PrimeFieldElement::to_big_uint(&x), x.to_big_uint());
    }

    fn assert_algorithm<B: FpInteger>(points: [FpPoint<B>; 2]) {
        for point in points {
            for scalar in [0_u32, 1, 2, 19, 255] {
                let scalar = B::from_u32(scalar).expect("small scalar fits");
                assert_eq!(
                    scalar_mul::<FpCurve<B>>(&point, &scalar),
                    point.mul_double_and_add(&scalar)
                );
            }
        }
    }

    #[test]
    fn neutral_algorithm_runs_on_both_fp_integer_backends() {
        assert_algorithm::<U256>([secp256k1().1, secp256r1().1]);
        assert_algorithm::<BigUint>([secp256k1_dynamic().1, secp256r1_dynamic().1]);
    }
}
