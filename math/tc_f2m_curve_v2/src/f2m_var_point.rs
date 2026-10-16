use crate::{F2mFieldElement, F2mVarCurve};
use core::fmt;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{BinaryFieldElement, CoordinateSystem, Curve, FieldElement, Point};

// BC's F2m coordinate systems. The lambda forms keep `l = x + y / x` in place of `y`, except
// at `x = 0`, where they keep `y` itself.
#[derive(Clone)]
enum Coords {
    Affine {
        x: F2mFieldElement,
        y: F2mFieldElement,
    },
    #[expect(dead_code)]
    Homogeneous {
        x: F2mFieldElement,
        y: F2mFieldElement,
        z: F2mFieldElement,
    },
    #[expect(dead_code)]
    LambdaAffine {
        x: F2mFieldElement,
        l: F2mFieldElement,
    },
    LambdaProjective {
        x: F2mFieldElement,
        l: F2mFieldElement,
        z: F2mFieldElement,
    },
}

/// A point of an [`F2mVarCurve`], `None` coordinates for infinity. Every method is variable
/// time and only for public points.
#[derive(Clone)]
pub struct F2mVarPoint<'a> {
    curve: &'a F2mVarCurve,
    coords: Option<Coords>,
}

impl<'a> F2mVarPoint<'a> {
    pub(crate) fn new(curve: &'a F2mVarCurve, x: F2mFieldElement, y: F2mFieldElement) -> Self {
        let coords = match curve.coordinate_system() {
            CoordinateSystem::Affine => Coords::Affine { x, y },
            CoordinateSystem::LambdaProjective => {
                let l = if x.is_zero() {
                    y
                } else {
                    divide(&y, &x).add(&x)
                };
                let z = curve.field().one();
                Coords::LambdaProjective { x, l, z }
            }
            _ => unreachable!("F2mVarCurve rejects unsupported coordinate systems"),
        };
        Self {
            curve,
            coords: Some(coords),
        }
    }

    pub(crate) fn infinity(curve: &'a F2mVarCurve) -> Self {
        Self {
            curve,
            coords: None,
        }
    }

    fn lambda_projective(
        &self,
        x: F2mFieldElement,
        l: F2mFieldElement,
        z: F2mFieldElement,
    ) -> Self {
        Self {
            curve: self.curve,
            coords: Some(Coords::LambdaProjective { x, l, z }),
        }
    }

    // BC returns the point (0, √b) whenever a lambda formula meets x = 0.
    fn x_zero(&self) -> Self {
        let field = self.curve.field();
        let y = self
            .curve
            .b()
            .sqrt()
            .expect("every element has a square root");
        self.lambda_projective(field.zero(), y, field.one())
    }

    /// BC's `SatisfiesCurveEquation`: `y² + xy = x³ + ax² + b`, in the point's coordinates.
    pub fn is_on_curve(&self) -> bool {
        let (a, b) = (self.curve.a(), self.curve.b());
        match &self.coords {
            None => true,
            Some(Coords::Affine { x, y }) => {
                y.add(x).multiply(y) == x.add(a).multiply(&x.square()).add(b)
            }
            Some(Coords::LambdaProjective { x, l, z }) => {
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
            Some(_) => unreachable!("F2mVarCurve rejects unsupported coordinate systems"),
        }
    }

    // BC's `AbstractF2mPoint.SatisfiesOrder`: with cofactor 2, a point of odd order is a
    // double, which holds when Tr(x + a) = 0, and Tr(a) = 1 on those curves.
    fn satisfies_order(&self) -> bool {
        let cofactor = self.curve.cofactor();
        if self.is_infinity() || cofactor.is_some_and(|h| *h == PaddedBigUint::from(1u8)) {
            return true;
        }
        if cofactor.is_some_and(|h| *h == PaddedBigUint::from(2u8)) {
            return self.x().expect("a finite point").trace() != 0;
        }
        self.curve
            .order()
            .is_none_or(|n| <&F2mVarCurve as Curve>::multiply(self, n).is_infinity())
    }

    pub fn subtract(&self, rhs: &Self) -> Self {
        self.add(&rhs.negate())
    }

    fn add_affine(&self, [x1, y1]: [&F2mFieldElement; 2], [x2, y2]: [&F2mFieldElement; 2]) -> Self {
        let dx = x1.add(x2);
        let dy = y1.add(y2);
        if dx.is_zero() {
            return if dy.is_zero() {
                self.twice()
            } else {
                Self::infinity(self.curve)
            };
        }
        let l = divide(&dy, &dx);
        let x3 = l.square().add(&l).add(&dx).add(self.curve.a());
        let y3 = l.multiply(&x1.add(&x3)).add(&x3).add(y1);
        Self::new(self.curve, x3, y3)
    }

    fn add_lambda_projective(
        &self,
        rhs: &Self,
        [x1, l1, z1]: [&F2mFieldElement; 3],
        [x2, l2, z2]: [&F2mFieldElement; 3],
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
            return self.lambda_projective(x3, l3, self.curve.field().one());
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

    fn twice_affine(&self, x1: &F2mFieldElement, y1: &F2mFieldElement) -> Self {
        let l1 = divide(y1, x1).add(x1);
        let x3 = l1.square().add(&l1).add(self.curve.a());
        let y3 = square_plus_product(x1, &x3, &l1.add(&self.curve.field().one()));
        Self::new(self.curve, x3, y3)
    }

    fn twice_lambda_projective(
        &self,
        x1: &F2mFieldElement,
        l1: &F2mFieldElement,
        z1: &F2mFieldElement,
    ) -> Self {
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
        let l3 = if b.bit_length() < self.curve.field().m() as usize / 2 {
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
                l3.add(&a.add(&self.curve.field().one()).multiply(&z3))
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
    fn twice_plus_lambda_projective(
        &self,
        rhs: &Self,
        [x1, l1, z1]: [&F2mFieldElement; 3],
    ) -> Self {
        let Some(Coords::LambdaProjective {
            x: x2,
            l: l2,
            z: z2,
        }) = &rhs.coords
        else {
            unreachable!("both points share the coordinate system")
        };
        if x2.is_zero() || !z2.is_one() {
            return self.twice().add(rhs);
        }

        let a = self.curve.a();
        let one = self.curve.field().one();
        let x1_sq = x1.square();
        let l1_sq = l1.square();
        let z1_sq = z1.square();
        let l1z1 = l1.multiply(z1);
        let t = a.multiply(&z1_sq).add(&l1_sq).add(&l1z1);
        let l2_plus_1 = l2.add(&one);
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

    fn raw_x(&self) -> Option<&F2mFieldElement> {
        match self.coords.as_ref()? {
            Coords::Affine { x, .. }
            | Coords::Homogeneous { x, .. }
            | Coords::LambdaAffine { x, .. }
            | Coords::LambdaProjective { x, .. } => Some(x),
        }
    }

    fn assert_same_curve(&self, rhs: &Self) {
        assert!(
            (core::ptr::eq(self.curve, rhs.curve) || self.curve == rhs.curve)
                && self.curve.coordinate_system() == rhs.curve.coordinate_system(),
            "points on different curves or coordinate systems"
        );
    }
}

fn divide(x: &F2mFieldElement, y: &F2mFieldElement) -> F2mFieldElement {
    x.multiply(&y.invert().expect("the divisor is not zero"))
}

// BC's `MultiplyPlusProduct`: `w·b + x·y`.
fn multiply_plus_product(
    w: &F2mFieldElement,
    b: &F2mFieldElement,
    x: &F2mFieldElement,
    y: &F2mFieldElement,
) -> F2mFieldElement {
    w.multiply(b).add(&x.multiply(y))
}

// BC's `SquarePlusProduct`: `w² + x·y`.
fn square_plus_product(
    w: &F2mFieldElement,
    x: &F2mFieldElement,
    y: &F2mFieldElement,
) -> F2mFieldElement {
    w.square().add(&x.multiply(y))
}

impl<'a> Point for F2mVarPoint<'a> {
    type Curve = &'a F2mVarCurve;

    fn curve(&self) -> &'a F2mVarCurve {
        self.curve
    }

    fn is_valid(&self) -> bool {
        self.is_on_curve() && self.satisfies_order()
    }

    fn infinity(&self) -> Self {
        Self::infinity(self.curve)
    }

    fn is_infinity(&self) -> bool {
        self.coords.is_none()
    }

    fn x(&self) -> Option<F2mFieldElement> {
        self.normalize().raw_x().cloned()
    }

    /// The affine `y`, recovered from `l` in the lambda form.
    fn y(&self) -> Option<F2mFieldElement> {
        match self.normalize().coords? {
            Coords::Affine { y, .. } => Some(y),
            Coords::LambdaProjective { x, l, .. } if x.is_zero() => Some(l),
            Coords::LambdaProjective { x, l, .. } => Some(l.add(&x).multiply(&x)),
            _ => unreachable!("F2mVarCurve rejects unsupported coordinate systems"),
        }
    }

    fn add(&self, rhs: &Self) -> Self {
        self.assert_same_curve(rhs);
        let (Some(left), Some(right)) = (&self.coords, &rhs.coords) else {
            return if self.is_infinity() {
                rhs.clone()
            } else {
                self.clone()
            };
        };
        match (left, right) {
            (Coords::Affine { x: x1, y: y1 }, Coords::Affine { x: x2, y: y2 }) => {
                self.add_affine([x1, y1], [x2, y2])
            }
            (
                Coords::LambdaProjective {
                    x: x1,
                    l: l1,
                    z: z1,
                },
                Coords::LambdaProjective {
                    x: x2,
                    l: l2,
                    z: z2,
                },
            ) => self.add_lambda_projective(rhs, [x1, l1, z1], [x2, l2, z2]),
            _ => unreachable!("both points share a supported coordinate system"),
        }
    }

    fn twice(&self) -> Self {
        let Some(x1) = self.raw_x() else {
            return self.clone();
        };
        if x1.is_zero() {
            // A point with x = 0 is its own negative.
            return Self::infinity(self.curve);
        }
        match self.coords.as_ref().expect("a finite point") {
            Coords::Affine { x, y } => self.twice_affine(x, y),
            Coords::LambdaProjective { x, l, z } => self.twice_lambda_projective(x, l, z),
            _ => unreachable!("F2mVarCurve rejects unsupported coordinate systems"),
        }
    }

    fn twice_plus(&self, rhs: &Self) -> Self {
        self.assert_same_curve(rhs);
        let Some(x1) = self.raw_x() else {
            return rhs.clone();
        };
        if rhs.is_infinity() {
            return self.twice();
        }
        if x1.is_zero() {
            return rhs.clone();
        }
        match self.coords.as_ref().expect("a finite point") {
            Coords::LambdaProjective { x, l, z } => {
                self.twice_plus_lambda_projective(rhs, [x, l, z])
            }
            _ => self.twice().add(rhs),
        }
    }

    fn negate(&self) -> Self {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        let coords = match coords {
            Coords::Affine { x, .. } | Coords::LambdaProjective { x, .. } if x.is_zero() => {
                return self.clone();
            }
            Coords::Affine { x, y } => Coords::Affine {
                x: x.clone(),
                y: y.add(x),
            },
            Coords::LambdaProjective { x, l, z } => Coords::LambdaProjective {
                x: x.clone(),
                l: l.add(z),
                z: z.clone(),
            },
            _ => unreachable!("F2mVarCurve rejects unsupported coordinate systems"),
        };
        Self {
            curve: self.curve,
            coords: Some(coords),
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

    fn projective_z(&self) -> Option<F2mFieldElement> {
        match self.coords.as_ref()? {
            Coords::Homogeneous { z, .. } | Coords::LambdaProjective { z, .. } => Some(z.clone()),
            _ => None,
        }
    }

    /// BC scales both `x` and `l` by `1/z` and leaves `z = 1`.
    fn normalize_with_inverse(&self, inverse: &F2mFieldElement) -> Self {
        match &self.coords {
            Some(Coords::LambdaProjective { x, l, .. }) => self.lambda_projective(
                x.multiply(inverse),
                l.multiply(inverse),
                self.curve.field().one(),
            ),
            _ => self.clone(),
        }
    }
}

/// The same point on the same curve, whatever the projective scale.
impl PartialEq for F2mVarPoint<'_> {
    fn eq(&self, other: &Self) -> bool {
        if !(core::ptr::eq(self.curve, other.curve) || self.curve == other.curve) {
            return false;
        }
        match (&self.coords, &other.coords) {
            (None, None) => true,
            (Some(Coords::Affine { x: x1, y: y1 }), Some(Coords::Affine { x: x2, y: y2 })) => {
                x1 == x2 && y1 == y2
            }
            (
                Some(Coords::LambdaProjective {
                    x: x1,
                    l: l1,
                    z: z1,
                }),
                Some(Coords::LambdaProjective {
                    x: x2,
                    l: l2,
                    z: z2,
                }),
            ) => x1.multiply(z2) == x2.multiply(z1) && l1.multiply(z2) == l2.multiply(z1),
            _ => false,
        }
    }
}

impl Eq for F2mVarPoint<'_> {}

/// Prints only whether the point is at infinity, never the coordinates.
impl fmt::Debug for F2mVarPoint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("F2mVarPoint")
            .field("infinity", &self.is_infinity())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use crate::{F2mField, F2mVarCurve, F2mVarPoint};
    use alloc::vec::Vec;
    use tc_bigint::{ArrayEncoding, PaddedBigUint};
    use tc_ec_core_v2::{CoordinateSystem, Curve, FieldElement, Point};

    const SYSTEMS: [CoordinateSystem; 2] =
        [CoordinateSystem::Affine, CoordinateSystem::LambdaProjective];

    fn bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn integer(text: &str) -> PaddedBigUint {
        <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes(text)).unwrap()
    }

    // SEC 2 sect163k1 and sect163r2: (b, n, Gx, Gy), both with a = 1 and h = 2.
    const CURVES: [[&str; 4]; 2] = [
        [
            "000000000000000000000000000000000000000001",
            "04000000000000000000020108A2E0CC0D99F8A5EF",
            "02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8",
            "0289070FB05D38FF58321F2E800536D538CCDAA3D9",
        ],
        [
            "020A601907B8C953CA1481EB10512F78744A3205FD",
            "040000000000000000000292FE77E70C12A4234C33",
            "03F0EBA16286A2D57EA0991168D4994637E8343E36",
            "00D51FBC6C71A0094FA2CDD545B11C5C0C797324F1",
        ],
    ];

    fn curves() -> Vec<(F2mVarCurve, [Vec<u8>; 2])> {
        let mut curves = Vec::new();
        for [b, n, gx, gy] in CURVES {
            for system in SYSTEMS {
                let curve = F2mVarCurve::new(
                    F2mField::pentanomial(163, 3, 6, 7).unwrap(),
                    &bytes("000000000000000000000000000000000000000001"),
                    &bytes(b),
                    Some(integer(n)),
                    Some(PaddedBigUint::from(2u8)),
                )
                .unwrap()
                .with_coordinate_system(system);
                curves.push((curve, [bytes(gx), bytes(gy)]));
            }
        }
        curves
    }

    fn generator<'a>(curve: &'a F2mVarCurve, [x, y]: &[Vec<u8>; 2]) -> F2mVarPoint<'a> {
        curve.create_point(x, y).unwrap()
    }

    #[test]
    fn the_sec_generators_are_valid_and_of_order_n() {
        for (curve, g) in &curves() {
            let g = generator(curve, g);
            assert!(
                g.is_on_curve() && g.is_valid(),
                "{:?}",
                curve.coordinate_system()
            );
            let n = curve.order().unwrap();
            assert!(<&F2mVarCurve as Curve>::multiply(&g, n).is_infinity());
        }
    }

    #[test]
    fn the_group_law_holds_on_the_generator() {
        for (curve, g) in &curves() {
            let g = generator(curve, g);
            let g2 = g.twice();
            let g3 = g2.add(&g);
            assert!(g2.is_on_curve() && g3.is_on_curve());
            assert_eq!(g.add(&g), g2);
            assert_eq!(g.add(&g2), g3);
            assert_eq!(g.twice_plus(&g), g3);
            assert_eq!(g2.twice_plus(&g.normalize()), g2.twice().add(&g));
            assert!(g.add(&g.negate()).is_infinity());
            assert_eq!(g3.subtract(&g2), g);
        }
    }

    #[test]
    fn affine_and_lambda_projective_reach_the_same_affine_point() {
        let k = integer("0123456789ABCDEF0123456789ABCDEF01234567");
        let curves = curves();
        for pair in curves.chunks(2) {
            let [(affine, g1), (lambda, g2)] = pair else {
                unreachable!()
            };
            let p = <&F2mVarCurve as Curve>::multiply(&generator(affine, g1), &k);
            let q = <&F2mVarCurve as Curve>::multiply(&generator(lambda, g2), &k);
            assert!(q.is_on_curve());
            assert_eq!(p.x(), q.x());
            assert_eq!(p.y(), q.y());
            assert!(!p.x().unwrap().is_zero());
        }
    }
}
