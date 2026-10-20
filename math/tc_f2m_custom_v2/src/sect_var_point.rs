use crate::SecTVarCurve;
use crate::sec1;
use crate::sect_element::SecTElement;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{Curve, Point, PointEncodeError};

/// A point of a [`SecTVarCurve`] in lambda-projective coordinates (X, L, Z), `None` for
/// infinity: `x = X/Z` and `L/Z = x + y/x`, or `y` itself where `x = 0`. Every method is
/// variable time and only for public points.
#[derive(Clone)]
pub struct SecTVarPoint<'a, F> {
    curve: &'a SecTVarCurve<F>,
    xlz: Option<(F, F, F)>,
}

impl<'a, F: SecTElement> SecTVarPoint<'a, F> {
    pub(crate) fn new(curve: &'a SecTVarCurve<F>, x: F, y: F) -> Self {
        let l = if x.is_zero() {
            y
        } else {
            divide(&y, &x).add(&x)
        };
        Self {
            curve,
            xlz: Some((x, l, F::one())),
        }
    }

    pub(crate) fn infinity(curve: &'a SecTVarCurve<F>) -> Self {
        Self { curve, xlz: None }
    }

    fn lambda_projective(&self, x: F, l: F, z: F) -> Self {
        Self {
            curve: self.curve,
            xlz: Some((x, l, z)),
        }
    }

    // BC returns the point (0, √b) whenever a lambda formula meets x = 0.
    fn x_zero(&self) -> Self {
        let y = self
            .curve
            .b()
            .sqrt()
            .expect("every element has a square root");
        self.lambda_projective(F::zero(), y, F::one())
    }

    /// BC's `SatisfiesCurveEquation`: `y² + xy = x³ + ax² + b`, in the point's coordinates.
    pub fn is_on_curve(&self) -> bool {
        let Some((x, l, z)) = &self.xlz else {
            return true;
        };
        let (a, b) = (self.curve.a(), self.curve.b());
        let z_is_one = z.is_one();
        if x.is_zero() {
            let rhs = if z_is_one {
                b.clone()
            } else {
                b.multiply(&z.square())
            };
            return l.square() == rhs;
        }
        let x2 = x.square();
        let (lhs, rhs) = if z_is_one {
            (l.square().add(l).add(a), x2.square().add(b))
        } else {
            let z2 = z.square();
            let z4 = z2.square();
            (
                multiply_plus_product(&l.add(z), l, a, &z2),
                square_plus_product(&x2, b, &z4),
            )
        };
        lhs.multiply(&x2) == rhs
    }

    // BC's `AbstractF2mPoint.SatisfiesOrder`: with cofactor 2, a point of odd order has
    // Tr(x) = 1.
    fn satisfies_order(&self) -> bool {
        if self.is_infinity() {
            return true;
        }
        let cofactor = self.curve.cofactor().expect("a SEC curve has a cofactor");
        if *cofactor == PaddedBigUint::from(2u8) {
            return self.x().expect("a finite point").trace() != 0;
        }
        let n = self.curve.order().expect("a SEC curve has an order");
        <&SecTVarCurve<F> as Curve>::multiply(self, n).is_infinity()
    }

    pub fn subtract(&self, rhs: &Self) -> Self {
        self.add(&rhs.negate())
    }

    pub fn encoded_length(&self, compressed: bool) -> usize {
        if self.is_infinity() {
            1
        } else {
            sec1::point_length::<F>(compressed)
        }
    }

    /// Writes the SEC 1 encoding of the normalized point into `output`; nothing is written when `output` is
    /// too short.
    pub fn encode_to(
        &self,
        compressed: bool,
        output: &mut [u8],
    ) -> Result<usize, PointEncodeError> {
        let affine = self.x().zip(self.y());
        sec1::encode(affine.as_ref(), compressed, output)
    }

    /// The SEC 1 encoding.
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let mut output = vec![0; self.encoded_length(compressed)];
        self.encode_to(compressed, &mut output)
            .expect("the buffer has the exact length");
        output
    }

    fn add_lambda_projective(
        &self,
        rhs: &Self,
        [x1, l1, z1]: [&F; 3],
        [x2, l2, z2]: [&F; 3],
    ) -> Self {
        if x1.is_zero() {
            return if x2.is_zero() {
                Self::infinity(self.curve)
            } else {
                rhs.add(self)
            };
        }

        let z1_is_one = z1.is_one();
        let (u2, s2) = if z1_is_one {
            (x2.clone(), l2.clone())
        } else {
            (x2.multiply(z1), l2.multiply(z1))
        };
        let z2_is_one = z2.is_one();
        let (u1, s1) = if z2_is_one {
            (x1.clone(), l1.clone())
        } else {
            (x1.multiply(z2), l1.multiply(z2))
        };
        let a = s1.add(&s2);
        let b = u1.add(&u2);
        if b.is_zero() {
            return if a.is_zero() {
                self.twice()
            } else {
                Self::infinity(self.curve)
            };
        }

        if x2.is_zero() {
            // The other point keeps its affine y; BC adds in affine form here.
            let normalized = self.normalize();
            let x1 = normalized.raw_x().expect("a finite point");
            let y1 = normalized.y().expect("a finite point");
            let l = divide(&y1.add(l2), x1);
            let x3 = l.square().add(&l).add(x1).add(self.curve.a());
            if x3.is_zero() {
                return self.x_zero();
            }
            let y3 = l.multiply(&x1.add(&x3)).add(&x3).add(&y1);
            let l3 = divide(&y3, &x3).add(&x3);
            return self.lambda_projective(x3, l3, F::one());
        }

        let b = b.square();
        let au1 = a.multiply(&u1);
        let au2 = a.multiply(&u2);
        let x3 = au1.multiply(&au2);
        if x3.is_zero() {
            return self.x_zero();
        }
        let mut abz2 = a.multiply(&b);
        if !z2_is_one {
            abz2 = abz2.multiply(z2);
        }
        let l3 = square_plus_product(&au2.add(&b), &abz2, &l1.add(z1));
        let mut z3 = abz2;
        if !z1_is_one {
            z3 = z3.multiply(z1);
        }
        self.lambda_projective(x3, l3, z3)
    }

    fn twice_lambda_projective(&self, x1: &F, l1: &F, z1: &F) -> Self {
        let (a, b) = (self.curve.a(), self.curve.b());
        let z1_is_one = z1.is_one();
        let l1z1 = if z1_is_one {
            l1.clone()
        } else {
            l1.multiply(z1)
        };
        let z1_sq = if z1_is_one { z1.clone() } else { z1.square() };
        let a_z1_sq = if z1_is_one {
            a.clone()
        } else {
            a.multiply(&z1_sq)
        };
        let t = l1.square().add(&l1z1).add(&a_z1_sq);
        if t.is_zero() {
            return self.x_zero();
        }

        let x3 = t.square();
        let z3 = if z1_is_one {
            t.clone()
        } else {
            t.multiply(&z1_sq)
        };
        let l3 = if self.curve.small_b() {
            let t1 = l1.add(x1).square();
            let t2 = if b.is_one() {
                a_z1_sq.add(&z1_sq).square()
            } else {
                square_plus_product(&a_z1_sq, b, &z1_sq.square())
            };
            let l3 = t1.add(&t).add(&z1_sq).multiply(&t1).add(&t2).add(&x3);
            if a.is_zero() {
                l3.add(&z3)
            } else if !a.is_one() {
                l3.add(&a.add(&F::one()).multiply(&z3))
            } else {
                l3
            }
        } else {
            let x1z1 = if z1_is_one {
                x1.clone()
            } else {
                x1.multiply(z1)
            };
            square_plus_product(&x1z1, &t, &l1z1).add(&x3).add(&z3)
        };
        self.lambda_projective(x3, l3, z3)
    }

    // BC optimizes 2P + Q only for a lambda-affine Q, a projective one with Z = 1.
    fn twice_plus_lambda_projective(&self, rhs: &Self, [x1, l1, z1]: [&F; 3]) -> Self {
        let (x2, l2, z2) = rhs.xlz.as_ref().expect("a finite point");
        if x2.is_zero() || !z2.is_one() {
            return self.twice().add(rhs);
        }

        let a = self.curve.a();
        let x1_sq = x1.square();
        let l1_sq = l1.square();
        let z1_sq = z1.square();
        let l1z1 = l1.multiply(z1);
        let t = a.multiply(&z1_sq).add(&l1_sq).add(&l1z1);
        let l2_plus_1 = l2.add(&F::one());
        let big_a = multiply_plus_product(
            &a.add(&l2_plus_1).multiply(&z1_sq).add(&l1_sq),
            &t,
            &x1_sq,
            &z1_sq,
        );
        let x2z1_sq = x2.multiply(&z1_sq);
        let big_b = x2z1_sq.add(&t).square();
        if big_b.is_zero() {
            return if big_a.is_zero() {
                rhs.twice()
            } else {
                Self::infinity(self.curve)
            };
        }
        if big_a.is_zero() {
            return self.x_zero();
        }

        let x3 = big_a.square().multiply(&x2z1_sq);
        let z3 = big_a.multiply(&big_b).multiply(&z1_sq);
        let l3 = multiply_plus_product(&big_a.add(&big_b).square(), &t, &l2_plus_1, &z3);
        self.lambda_projective(x3, l3, z3)
    }

    fn raw_x(&self) -> Option<&F> {
        self.xlz.as_ref().map(|(x, _, _)| x)
    }

    fn assert_same_curve(&self, rhs: &Self) {
        assert!(
            core::ptr::eq(self.curve, rhs.curve) || self.curve == rhs.curve,
            "points on different curves"
        );
    }
}

fn divide<F: SecTElement>(x: &F, y: &F) -> F {
    x.multiply(&y.invert().expect("the divisor is not zero"))
}

// BC's `MultiplyPlusProduct`: `w·b + x·y`.
fn multiply_plus_product<F: SecTElement>(w: &F, b: &F, x: &F, y: &F) -> F {
    w.multiply(b).add(&x.multiply(y))
}

// BC's `SquarePlusProduct`: `w² + x·y`.
fn square_plus_product<F: SecTElement>(w: &F, x: &F, y: &F) -> F {
    w.square().add(&x.multiply(y))
}

impl<'a, F: SecTElement> Point for SecTVarPoint<'a, F> {
    type Curve = &'a SecTVarCurve<F>;

    fn curve(&self) -> &'a SecTVarCurve<F> {
        self.curve
    }

    fn is_valid(&self) -> bool {
        self.is_on_curve() && self.satisfies_order()
    }

    fn infinity(&self) -> Self {
        Self::infinity(self.curve)
    }

    fn is_infinity(&self) -> bool {
        self.xlz.is_none()
    }

    fn x(&self) -> Option<F> {
        self.normalize().raw_x().cloned()
    }

    /// The affine `y`, recovered from `l`.
    fn y(&self) -> Option<F> {
        let (x, l, _) = self.normalize().xlz?;
        if x.is_zero() {
            Some(l)
        } else {
            Some(l.add(&x).multiply(&x))
        }
    }

    fn add(&self, rhs: &Self) -> Self {
        self.assert_same_curve(rhs);
        let (Some((x1, l1, z1)), Some((x2, l2, z2))) = (&self.xlz, &rhs.xlz) else {
            return if self.is_infinity() {
                rhs.clone()
            } else {
                self.clone()
            };
        };
        self.add_lambda_projective(rhs, [x1, l1, z1], [x2, l2, z2])
    }

    fn twice(&self) -> Self {
        let Some((x, l, z)) = &self.xlz else {
            return self.clone();
        };
        if x.is_zero() {
            // A point with x = 0 is its own negative.
            return Self::infinity(self.curve);
        }
        self.twice_lambda_projective(x, l, z)
    }

    fn twice_plus(&self, rhs: &Self) -> Self {
        self.assert_same_curve(rhs);
        let Some((x, l, z)) = &self.xlz else {
            return rhs.clone();
        };
        if rhs.is_infinity() {
            return self.twice();
        }
        if x.is_zero() {
            return rhs.clone();
        }
        self.twice_plus_lambda_projective(rhs, [x, l, z])
    }

    fn negate(&self) -> Self {
        match &self.xlz {
            Some((x, l, z)) if !x.is_zero() => {
                self.lambda_projective(x.clone(), l.add(z), z.clone())
            }
            _ => self.clone(),
        }
    }

    fn normalize(&self) -> Self {
        match self.projective_z() {
            Some(z) if !z.is_one() => {
                let inverse = z.invert().expect("a finite point has a nonzero Z");
                self.normalize_with_inverse(&inverse)
            }
            _ => self.clone(),
        }
    }

    fn projective_z(&self) -> Option<F> {
        self.xlz.as_ref().map(|(_, _, z)| z.clone())
    }

    /// BC scales `x` and `l` by `1/z` and leaves `z = 1`.
    fn normalize_with_inverse(&self, inverse: &F) -> Self {
        match &self.xlz {
            Some((x, l, _)) => {
                self.lambda_projective(x.multiply(inverse), l.multiply(inverse), F::one())
            }
            None => self.clone(),
        }
    }
}

/// The same point on the same curve, whatever the projective scale.
impl<F: SecTElement> PartialEq for SecTVarPoint<'_, F> {
    fn eq(&self, other: &Self) -> bool {
        if !(core::ptr::eq(self.curve, other.curve) || self.curve == other.curve) {
            return false;
        }
        match (&self.xlz, &other.xlz) {
            (None, None) => true,
            (Some((x1, l1, z1)), Some((x2, l2, z2))) => {
                x1.multiply(z2) == x2.multiply(z1) && l1.multiply(z2) == l2.multiply(z1)
            }
            _ => false,
        }
    }
}

impl<F: SecTElement> Eq for SecTVarPoint<'_, F> {}

/// Prints only whether the point is at infinity, never the coordinates.
impl<F> fmt::Debug for SecTVarPoint<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecTVarPoint")
            .field("infinity", &self.xlz.is_none())
            .finish_non_exhaustive()
    }
}
