use crate::secp_element::SecPElement;
use crate::{SecPVarCurve, sec1};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{Curve, Point, PointEncodeError, wnaf};

/// A point of a [`SecPVarCurve`], in Jacobian coordinates (X, Y, Z) for the affine
/// (X / Z², Y / Z³). Variable time; only for public points.
#[derive(Clone)]
pub struct SecPVarPoint<'a, F> {
    curve: &'a SecPVarCurve<F>,
    xyz: Option<(F, F, F)>,
}

impl<'a, F: SecPElement> SecPVarPoint<'a, F> {
    pub(crate) fn new(curve: &'a SecPVarCurve<F>, x: F, y: F) -> Self {
        Self {
            curve,
            xyz: Some((x, y, F::one())),
        }
    }

    pub(crate) fn infinity(curve: &'a SecPVarCurve<F>) -> Self {
        Self { curve, xyz: None }
    }

    fn with(&self, x: F, y: F, z: F) -> Self {
        Self {
            curve: self.curve,
            xyz: Some((x, y, z)),
        }
    }

    /// Whether `Y² = X³ + aXZ⁴ + bZ⁶`; infinity counts as on the curve. The subgroup is not
    /// checked; see [`is_valid`](Point::is_valid).
    pub fn is_on_curve(&self) -> bool {
        let Some((x, y, z)) = &self.xyz else {
            return true;
        };
        let (mut a, mut b) = (self.curve.a().clone(), self.curve.b().clone());
        if !z.is_one() {
            let z2 = z.square();
            let z4 = z2.square();
            a = a.multiply(&z4);
            b = b.multiply(&z2.multiply(&z4));
        }
        y.square() == x.square().add(&a).multiply(x).add(&b)
    }

    /// `P - Q`. Panics when the curves differ.
    pub fn subtract(&self, rhs: &Self) -> Self {
        self.add(&rhs.negate())
    }

    /// The exact length of the SEC 1 encoding.
    pub fn encoded_length(&self, compressed: bool) -> usize {
        if self.is_infinity() {
            1
        } else {
            self.curve.affine_point_encoding_length(compressed)
        }
    }

    /// Writes the SEC 1 encoding into `output`, normalizing once; nothing is written when
    /// `output` is too short.
    pub fn encode_to(
        &self,
        compressed: bool,
        output: &mut [u8],
    ) -> Result<usize, PointEncodeError> {
        let affine = self.normalize().xyz.map(|(x, y, _)| (x, y));
        sec1::encode(affine.as_ref(), compressed, output)
    }

    /// The SEC 1 encoding.
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let mut output = vec![0; self.encoded_length(compressed)];
        self.encode_to(compressed, &mut output)
            .expect("the buffer has the exact length");
        output
    }

    // BC's `ScaleXPointMap`, through `ECPoint.ScaleX`: X times `scale`, Y and Z as they are.
    pub(crate) fn scale_x(&self, scale: &F) -> Self {
        match &self.xyz {
            None => self.clone(),
            Some((x, y, z)) => self.with(x.multiply(scale), y.clone(), z.clone()),
        }
    }

    fn assert_same_curve(&self, rhs: &Self) {
        assert!(
            core::ptr::eq(self.curve, rhs.curve) || self.curve == rhs.curve,
            "points on different curves"
        );
    }

    // BC's `FpPoint.Add` for Jacobian points, with its shortcut for equal Z.
    fn add_jacobian(&self, left: &(F, F, F), right: &(F, F, F)) -> Self {
        let (x1, y1, z1) = left;
        let (x2, y2, z2) = right;
        let z1_is_one = z1.is_one();

        if !z1_is_one && z1 == z2 {
            let dx = x1.subtract(x2);
            let dy = y1.subtract(y2);
            if dx.is_zero() {
                return if dy.is_zero() {
                    self.twice()
                } else {
                    Self::infinity(self.curve)
                };
            }
            let c = dx.square();
            let w1 = x1.multiply(&c);
            let w2 = x2.multiply(&c);
            let a1 = w1.subtract(&w2).multiply(y1);
            let x3 = dy.square().subtract(&w1).subtract(&w2);
            let y3 = w1.subtract(&x3).multiply(&dy).subtract(&a1);
            let z3 = dx.multiply(z1);
            return self.with(x3, y3, z3);
        }

        let (u2, s2) = if z1_is_one {
            (x2.clone(), y2.clone())
        } else {
            let z1_squared = z1.square();
            let z1_cubed = z1_squared.multiply(z1);
            (z1_squared.multiply(x2), z1_cubed.multiply(y2))
        };
        let z2_is_one = z2.is_one();
        let (u1, s1) = if z2_is_one {
            (x1.clone(), y1.clone())
        } else {
            let z2_squared = z2.square();
            let z2_cubed = z2_squared.multiply(z2);
            (z2_squared.multiply(x1), z2_cubed.multiply(y1))
        };
        let h = u1.subtract(&u2);
        let r = s1.subtract(&s2);
        if h.is_zero() {
            return if r.is_zero() {
                self.twice()
            } else {
                Self::infinity(self.curve)
            };
        }
        let h_squared = h.square();
        let g = h_squared.multiply(&h);
        let v = h_squared.multiply(&u1);
        let x3 = r.square().add(&g).subtract(&double(&v));
        let y3 = v.subtract(&x3).multiply(&r).subtract(&g.multiply(&s1));
        let mut z3 = h;
        if !z1_is_one {
            z3 = z3.multiply(z1);
        }
        if !z2_is_one {
            z3 = z3.multiply(z2);
        }
        self.with(x3, y3, z3)
    }

    // BC's `FpPoint.Twice` for Jacobian points, taking (X + Z²)(X - Z²) for 3X² + aZ⁴ when
    // a = -3, as BC's `SecP*R1Point`s do.
    fn twice_jacobian(&self, x: &F, y: &F, z: &F) -> Self {
        let z_is_one = z.is_one();
        let y_squared = y.square();
        let t = y_squared.square();
        let a = self.curve.a();

        let (m, s) = if self.curve.a_is_minus_three() {
            let z_squared = if z_is_one { z.clone() } else { z.square() };
            let product = x.add(&z_squared).multiply(&x.subtract(&z_squared));
            (three(&product), four(&y_squared.multiply(x)))
        } else {
            let mut m = three(&x.square());
            if z_is_one {
                m = m.add(a);
            } else if !a.is_zero() {
                m = m.add(&z.square().square().multiply(a));
            }
            (m, four(&x.multiply(&y_squared)))
        };

        let x3 = m.square().subtract(&double(&s));
        let y3 = s.subtract(&x3).multiply(&m).subtract(&double(&four(&t)));
        let mut z3 = double(y);
        if !z_is_one {
            z3 = z3.multiply(z);
        }
        self.with(x3, y3, z3)
    }
}

fn double<F: SecPElement>(value: &F) -> F {
    value.add(value)
}

fn three<F: SecPElement>(value: &F) -> F {
    double(value).add(value)
}

fn four<F: SecPElement>(value: &F) -> F {
    double(&double(value))
}

/// Variable time; only for public points.
impl<'a, F: SecPElement> Point for SecPVarPoint<'a, F> {
    type Curve = &'a SecPVarCurve<F>;

    fn curve(&self) -> &'a SecPVarCurve<F> {
        self.curve
    }

    /// On the curve and, when the cofactor is not one, `nP = O`.
    fn is_valid(&self) -> bool {
        let curve = self.curve;
        self.is_on_curve()
            && (self.is_infinity()
                || *curve.cofactor().expect("a SEC curve has a cofactor")
                    == PaddedBigUint::from(1u8)
                || wnaf::wnaf_mul_point::<&SecPVarCurve<F>>(
                    self,
                    curve.order().expect("a SEC curve has an order"),
                )
                .is_infinity())
    }

    fn infinity(&self) -> Self {
        Self::infinity(self.curve)
    }

    fn is_infinity(&self) -> bool {
        self.xyz.is_none()
    }

    /// The affine x, normalizing first.
    fn x(&self) -> Option<F> {
        self.normalize().xyz.map(|(x, _, _)| x)
    }

    /// The affine y, normalizing first.
    fn y(&self) -> Option<F> {
        self.normalize().xyz.map(|(_, y, _)| y)
    }

    /// `P + Q`. Panics when the curves differ.
    fn add(&self, rhs: &Self) -> Self {
        self.assert_same_curve(rhs);
        match (&self.xyz, &rhs.xyz) {
            (None, _) => rhs.clone(),
            (_, None) => self.clone(),
            (Some(left), Some(right)) => self.add_jacobian(left, right),
        }
    }

    /// `2P`.
    fn twice(&self) -> Self {
        match &self.xyz {
            None => self.clone(),
            Some((_, y, _)) if y.is_zero() => Self::infinity(self.curve),
            Some((x, y, z)) => self.twice_jacobian(x, y, z),
        }
    }

    /// `-P`.
    fn negate(&self) -> Self {
        match &self.xyz {
            None => self.clone(),
            Some((x, y, z)) => self.with(x.clone(), y.negate(), z.clone()),
        }
    }

    /// The same point with `Z = 1`, at the cost of one inversion.
    fn normalize(&self) -> Self {
        match &self.xyz {
            Some((_, _, z)) if !z.is_one() => {
                let inverse = z.invert().expect("a finite point has a nonzero Z");
                self.normalize_with_inverse(&inverse)
            }
            _ => self.clone(),
        }
    }

    fn projective_z(&self) -> Option<F> {
        self.xyz.as_ref().map(|(_, _, z)| z.clone())
    }

    fn normalize_with_inverse(&self, inverse: &F) -> Self {
        let Some((x, y, _)) = &self.xyz else {
            return self.clone();
        };
        let inverse2 = inverse.square();
        let inverse3 = inverse2.multiply(inverse);
        Self::new(self.curve, x.multiply(&inverse2), y.multiply(&inverse3))
    }
}

/// The same point on the same curve, whatever the projective scale: `X₁Z₂² = X₂Z₁²` and
/// `Y₁Z₂³ = Y₂Z₁³`.
impl<F: SecPElement> PartialEq for SecPVarPoint<'_, F> {
    fn eq(&self, other: &Self) -> bool {
        if !(core::ptr::eq(self.curve, other.curve) || self.curve == other.curve) {
            return false;
        }
        let (Some((x1, y1, z1)), Some((x2, y2, z2))) = (&self.xyz, &other.xyz) else {
            return self.is_infinity() && other.is_infinity();
        };
        let (z1_squared, z2_squared) = (z1.square(), z2.square());
        x1.multiply(&z2_squared) == x2.multiply(&z1_squared)
            && y1.multiply(&z2_squared.multiply(z2)) == y2.multiply(&z1_squared.multiply(z1))
    }
}

impl<F: SecPElement> Eq for SecPVarPoint<'_, F> {}

impl<F> fmt::Debug for SecPVarPoint<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecPVarPoint").finish_non_exhaustive()
    }
}
