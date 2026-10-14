use core::fmt;
use core::ops::{Add, Neg, Sub};

use crate::{FpCurve, FpFieldElement};

/// An affine point; `xy` is `None` at infinity.
#[derive(Clone)]
pub struct FpPoint<'a> {
    curve: &'a FpCurve<'a>,
    xy: Option<(FpFieldElement<'a>, FpFieldElement<'a>)>,
}

impl<'a> FpPoint<'a> {
    pub(crate) fn new(
        curve: &'a FpCurve<'a>,
        x: FpFieldElement<'a>,
        y: FpFieldElement<'a>,
    ) -> Self {
        Self {
            curve,
            xy: Some((x, y)),
        }
    }

    pub(crate) fn infinity(curve: &'a FpCurve<'a>) -> Self {
        Self { curve, xy: None }
    }

    pub fn curve(&self) -> &'a FpCurve<'a> {
        self.curve
    }

    pub fn is_infinity(&self) -> bool {
        self.xy.is_none()
    }

    pub fn x(&self) -> Option<&FpFieldElement<'a>> {
        self.xy.as_ref().map(|(x, _)| x)
    }

    pub fn y(&self) -> Option<&FpFieldElement<'a>> {
        self.xy.as_ref().map(|(_, y)| y)
    }

    /// Whether `y² = x³ + ax + b`; infinity counts as on the curve. Membership in the
    /// subgroup of the order is not checked. Variable time; only for public points.
    pub fn is_on_curve(&self) -> bool {
        let Some((x, y)) = &self.xy else {
            return true;
        };
        let rhs = &(&(&x.square() + self.curve.a()) * x) + self.curve.b();
        y.square() == rhs
    }

    /// `2P`. Variable time; only for public points.
    pub fn twice(&self) -> Self {
        let Some((x, y)) = &self.xy else {
            return self.clone();
        };
        if y.is_zero() {
            return Self::infinity(self.curve);
        }
        let x_squared = x.square();
        let numerator = &(&x_squared.double() + &x_squared) + self.curve.a();
        let inverse = y.double().invert().expect("2y is not zero");
        self.chord(x, y, x, &(&numerator * &inverse))
    }

    fn chord(
        &self,
        x1: &FpFieldElement<'a>,
        y1: &FpFieldElement<'a>,
        x2: &FpFieldElement<'a>,
        gamma: &FpFieldElement<'a>,
    ) -> Self {
        let x3 = &(&gamma.square() - x1) - x2;
        let y3 = &(gamma * &(x1 - &x3)) - y1;
        Self::new(self.curve, x3, y3)
    }

    fn assert_same_curve(&self, rhs: &Self) {
        assert!(
            core::ptr::eq(self.curve, rhs.curve) || self.curve == rhs.curve,
            "points on different curves"
        );
    }
}

/// `P + Q`. Variable time; only for public points. Panics when the curves differ.
impl<'a> Add for &FpPoint<'a> {
    type Output = FpPoint<'a>;

    fn add(self, rhs: Self) -> FpPoint<'a> {
        self.assert_same_curve(rhs);
        let (Some((x1, y1)), Some((x2, y2))) = (&self.xy, &rhs.xy) else {
            return if self.is_infinity() {
                rhs.clone()
            } else {
                self.clone()
            };
        };
        let dx = x2 - x1;
        let dy = y2 - y1;
        if dx.is_zero() {
            return if dy.is_zero() {
                self.twice()
            } else {
                FpPoint::infinity(self.curve)
            };
        }
        let inverse = dx.invert().expect("dx is not zero");
        self.chord(x1, y1, x2, &(&dy * &inverse))
    }
}

/// `P - Q`. Variable time; only for public points. Panics when the curves differ.
impl<'a> Sub for &FpPoint<'a> {
    type Output = FpPoint<'a>;

    fn sub(self, rhs: Self) -> FpPoint<'a> {
        self + &-rhs
    }
}

/// `-P`. Constant time.
impl<'a> Neg for &FpPoint<'a> {
    type Output = FpPoint<'a>;

    fn neg(self) -> FpPoint<'a> {
        FpPoint {
            curve: self.curve,
            xy: self.xy.as_ref().map(|(x, y)| (x.clone(), -y)),
        }
    }
}

/// Same curve and coordinates.
impl PartialEq for FpPoint<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.curve == other.curve && self.xy == other.xy
    }
}

impl Eq for FpPoint<'_> {}

/// Prints only whether the point is at infinity, never the coordinates, which may be secret.
impl fmt::Debug for FpPoint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FpPoint")
            .field("infinity", &self.is_infinity())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use tc_bigint::PaddedBigUint;

    use crate::{FpCurve, FpField};

    fn int(value: u8) -> PaddedBigUint {
        PaddedBigUint::from(value)
    }

    fn coordinates(point: &crate::FpPoint<'_>) -> (PaddedBigUint, PaddedBigUint) {
        (
            point.x().unwrap().to_big_uint(),
            point.y().unwrap().to_big_uint(),
        )
    }

    #[test]
    fn sums_and_doubles_match_the_textbook_curve_over_f23() {
        let field = FpField::new(int(23));
        let curve = FpCurve::new(&field, &int(1), &int(1), None, None);
        let p = curve.create_point(&int(3), &int(10));
        let q = curve.create_point(&int(9), &int(7));
        assert_eq!(coordinates(&(&p + &q)), (int(17), int(20)));
        assert_eq!(coordinates(&p.twice()), (int(7), int(12)));
        assert_eq!(&p + &p, p.twice());
        assert_eq!(&(&p + &q) - &q, p);
    }

    #[test]
    fn a_point_plus_its_negation_is_infinity_and_infinity_is_neutral() {
        let field = FpField::new(int(23));
        let curve = FpCurve::new(&field, &int(1), &int(1), None, None);
        let p = curve.create_point(&int(3), &int(10));
        assert!((&p + &-&p).is_infinity());
        assert_eq!(&p + &curve.infinity(), p);
        assert_eq!(&curve.infinity() + &p, p);
        assert!(curve.infinity().twice().is_infinity());
    }

    #[test]
    fn only_points_satisfying_the_equation_are_on_the_curve() {
        let field = FpField::new(int(23));
        let curve = FpCurve::new(&field, &int(1), &int(1), None, None);
        let p = curve.create_point(&int(3), &int(10));
        assert!(p.is_on_curve());
        assert!(p.twice().is_on_curve());
        assert!(curve.infinity().is_on_curve());
        assert!(!curve.create_point(&int(3), &int(11)).is_on_curve());
    }
}
