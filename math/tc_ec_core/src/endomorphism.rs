//! Public-scalar endomorphisms and coordinate maps.
use crate::{AlgorithmError, Curve, FieldElement, Point, sum_of_two_multiplies};

/// A map on points of a particular curve.
pub trait PointMap<P: Point> {
    /// Applies the map. Implementations specify whether this preserves the curve.
    fn map(&self, point: &P) -> P;
}

/// Scales affine X, affine Y, or both, optionally negating the other coordinate.
#[derive(Clone)]
pub struct ScalePointMap<F> {
    /// X multiplier.
    pub x: F,
    /// Y multiplier.
    pub y: F,
}

impl<P: Point> PointMap<P> for ScalePointMap<<P::Curve as Curve>::Field> {
    fn map(&self, point: &P) -> P {
        if point.is_identity() {
            return point.clone();
        }
        let point = point.normalize();
        point.curve().create_point(
            point.x().unwrap().mul(&self.x),
            point.y().unwrap().mul(&self.y),
        )
    }
}

/// A GLV map and matching signed scalar decomposition.
/// Implementors must ensure `kP = k1 P + k2 map(P)` in the intended subgroup.
pub trait GlvEndomorphism<C: Curve>: PointMap<C::Point> {
    /// Returns unsigned magnitudes and negative flags. Variable time.
    fn decompose_scalar(&self, scalar: &C::Scalar) -> [(C::Scalar, bool); 2];
}

/// Computes a public scalar multiple with a GLV decomposition.
pub fn glv_mul<C: Curve, E: GlvEndomorphism<C>>(
    point: &C::Point,
    scalar: &C::Scalar,
    endomorphism: &E,
) -> Result<C::Point, AlgorithmError> {
    let [(a, negative_a), (b, negative_b)] = endomorphism.decompose_scalar(scalar);
    let p = if negative_a {
        point.negate()
    } else {
        point.clone()
    };
    let mapped = endomorphism.map(point);
    let q = if negative_b { mapped.negate() } else { mapped };
    sum_of_two_multiplies::<C>(&p, &a, &q, &b)
}
