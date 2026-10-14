use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Add, Mul, Neg, Sub};

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{CoordinateSystem, PointEncodeError};

use crate::{FpCurve, FpFieldElement};

#[derive(Clone)]
enum Coords<'a> {
    Affine {
        x: FpFieldElement<'a>,
        y: FpFieldElement<'a>,
    },
    Homogeneous {
        x: FpFieldElement<'a>,
        y: FpFieldElement<'a>,
        z: FpFieldElement<'a>,
    },
    Jacobian {
        x: FpFieldElement<'a>,
        y: FpFieldElement<'a>,
        z: FpFieldElement<'a>,
    },
    JacobianModified {
        x: FpFieldElement<'a>,
        y: FpFieldElement<'a>,
        z: FpFieldElement<'a>,
        az4: Option<FpFieldElement<'a>>,
    },
}

impl<'a> Coords<'a> {
    fn x(&self) -> &FpFieldElement<'a> {
        match self {
            Self::Affine { x, .. }
            | Self::Homogeneous { x, .. }
            | Self::Jacobian { x, .. }
            | Self::JacobianModified { x, .. } => x,
        }
    }

    fn y(&self) -> &FpFieldElement<'a> {
        match self {
            Self::Affine { y, .. }
            | Self::Homogeneous { y, .. }
            | Self::Jacobian { y, .. }
            | Self::JacobianModified { y, .. } => y,
        }
    }

    fn z(&self) -> Option<&FpFieldElement<'a>> {
        match self {
            Self::Affine { .. } => None,
            Self::Homogeneous { z, .. }
            | Self::Jacobian { z, .. }
            | Self::JacobianModified { z, .. } => Some(z),
        }
    }

    // Powers of Z in x = X / Z^px and y = Y / Z^py.
    fn powers(&self) -> (u32, u32) {
        match self {
            Self::Affine { .. } => (0, 0),
            Self::Homogeneous { .. } => (1, 1),
            Self::Jacobian { .. } | Self::JacobianModified { .. } => (2, 3),
        }
    }
}

/// A point on an [`FpCurve`], in the coordinate system of the curve; `None` is infinity.
///
/// The formulas are BC's, and branch on the coordinates and invert; every
/// method is variable time and only for public points.
#[derive(Clone)]
pub struct FpPoint<'a> {
    curve: &'a FpCurve<'a>,
    coords: Option<Coords<'a>>,
}

impl<'a> FpPoint<'a> {
    pub(crate) fn new(
        curve: &'a FpCurve<'a>,
        x: FpFieldElement<'a>,
        y: FpFieldElement<'a>,
    ) -> Self {
        let one = curve.field().one();
        let coords = match curve.coordinate_system() {
            CoordinateSystem::Affine => Coords::Affine { x, y },
            CoordinateSystem::Homogeneous => Coords::Homogeneous { x, y, z: one },
            CoordinateSystem::Jacobian => Coords::Jacobian { x, y, z: one },
            CoordinateSystem::JacobianModified => Coords::JacobianModified {
                x,
                y,
                z: one,
                az4: Some(curve.a().clone()),
            },
            _ => unreachable!("FpCurve rejects unsupported coordinate systems"),
        };
        Self {
            curve,
            coords: Some(coords),
        }
    }

    pub(crate) fn infinity(curve: &'a FpCurve<'a>) -> Self {
        Self {
            curve,
            coords: None,
        }
    }

    fn with_coords(&self, coords: Coords<'a>) -> Self {
        Self {
            curve: self.curve,
            coords: Some(coords),
        }
    }

    pub fn curve(&self) -> &'a FpCurve<'a> {
        self.curve
    }

    pub fn is_infinity(&self) -> bool {
        self.coords.is_none()
    }

    /// X as stored, which is not the affine x under a projective system; see [`x`](Self::x).
    pub fn raw_x(&self) -> Option<&FpFieldElement<'a>> {
        self.coords.as_ref().map(Coords::x)
    }

    /// Y as stored, which is not the affine y under a projective system; see [`y`](Self::y).
    pub fn raw_y(&self) -> Option<&FpFieldElement<'a>> {
        self.coords.as_ref().map(Coords::y)
    }

    /// The projective Z at `index`: 0 is Z, and 1 is `aZ⁴` under modified Jacobian.
    pub fn z_coord(&self, index: usize) -> Option<FpFieldElement<'a>> {
        match (self.coords.as_ref()?, index) {
            (
                Coords::Homogeneous { z, .. }
                | Coords::Jacobian { z, .. }
                | Coords::JacobianModified { z, .. },
                0,
            ) => Some(z.clone()),
            (Coords::JacobianModified { .. }, 1) => Some(self.jacobian_modified_w()),
            _ => None,
        }
    }

    /// The affine x, normalizing first.
    pub fn x(&self) -> Option<FpFieldElement<'a>> {
        self.normalize().raw_x().cloned()
    }

    /// The affine y, normalizing first.
    pub fn y(&self) -> Option<FpFieldElement<'a>> {
        self.normalize().raw_y().cloned()
    }

    /// Whether the point is affine, infinity, or projective with `Z = 1`.
    pub fn is_normalized(&self) -> bool {
        self.coords
            .as_ref()
            .is_none_or(|coords| coords.z().is_none_or(FpFieldElement::is_one))
    }

    /// The same point with `Z = 1`, at the cost of one inversion.
    pub fn normalize(&self) -> Self {
        match self.coords.as_ref().and_then(Coords::z) {
            Some(z) if !z.is_one() => {
                let inverse = z.invert().expect("a finite point has a nonzero Z");
                self.normalize_with_inverse(&inverse)
            }
            _ => self.clone(),
        }
    }

    pub(crate) fn normalize_with_inverse(&self, inverse: &FpFieldElement<'a>) -> Self {
        let (x, y) = match &self.coords {
            None | Some(Coords::Affine { .. }) => return self.clone(),
            Some(Coords::Homogeneous { x, y, .. }) => (x * inverse, y * inverse),
            Some(Coords::Jacobian { x, y, .. } | Coords::JacobianModified { x, y, .. }) => {
                let inverse2 = inverse.square();
                let inverse3 = &inverse2 * inverse;
                (x * &inverse2, y * &inverse3)
            }
        };
        Self::new(self.curve, x, y)
    }

    /// Whether `y² = x³ + ax + b`; infinity counts as on the curve. The subgroup is
    /// not checked; see [`is_valid`](Self::is_valid).
    pub fn is_on_curve(&self) -> bool {
        let Some(coords) = &self.coords else {
            return true;
        };
        let (x, y) = (coords.x(), coords.y());
        let mut lhs = y.square();
        let mut a = self.curve.a().clone();
        let mut b = self.curve.b().clone();
        match coords {
            Coords::Homogeneous { z, .. } if !z.is_one() => {
                let z2 = z.square();
                lhs = &lhs * z;
                a = &a * &z2;
                b = &b * &(&z2 * z);
            }
            Coords::Jacobian { z, .. } | Coords::JacobianModified { z, .. } if !z.is_one() => {
                let z2 = z.square();
                let z4 = z2.square();
                a = &a * &z4;
                b = &b * &(&z2 * &z4);
            }
            _ => {}
        }
        lhs == &(&(&x.square() + &a) * x) + &b
    }

    /// On the curve and, when the cofactor is not one and the order is known, `nP = O`.
    pub fn is_valid(&self) -> bool {
        self.is_on_curve() && self.satisfies_order()
    }

    fn satisfies_order(&self) -> bool {
        if self.is_infinity()
            || self
                .curve
                .cofactor()
                .is_some_and(|h| *h == PaddedBigUint::from(1u8))
        {
            return true;
        }
        self.curve.order().is_none_or(|n| (self * n).is_infinity())
    }

    /// `2P`.
    pub fn twice(&self) -> Self {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        if coords.y().is_zero() {
            return Self::infinity(self.curve);
        }
        match coords {
            Coords::Affine { x, y } => self.twice_affine(x, y),
            Coords::Homogeneous { x, y, z } => self.twice_homogeneous(x, y, z),
            Coords::Jacobian { x, y, z } => self.twice_jacobian(x, y, z),
            Coords::JacobianModified { .. } => self.twice_jacobian_modified(true),
        }
    }

    fn twice_affine(&self, x: &FpFieldElement<'a>, y: &FpFieldElement<'a>) -> Self {
        let numerator = &three(&x.square()) + self.curve.a();
        let gamma = &numerator * &y.double().invert().expect("2y is not zero");
        let x3 = &gamma.square() - &x.double();
        let y3 = &(&gamma * &(x - &x3)) - y;
        Self::new(self.curve, x3, y3)
    }

    fn twice_homogeneous(
        &self,
        x: &FpFieldElement<'a>,
        y: &FpFieldElement<'a>,
        z: &FpFieldElement<'a>,
    ) -> Self {
        let z_is_one = z.is_one();
        let mut w = self.curve.a().clone();
        if !w.is_zero() && !z_is_one {
            w = &w * &z.square();
        }
        w = &w + &three(&x.square());

        let s = if z_is_one { y.clone() } else { y * z };
        let t = if z_is_one { y.square() } else { &s * y };
        let b = x * &t;
        let four_b = four(&b);
        let h = &w.square() - &four_b.double();
        let two_s = s.double();
        let x3 = &h * &two_s;
        let two_t = t.double();
        let y3 = &(&(&four_b - &h) * &w) - &two_t.square().double();
        let four_s_squared = if z_is_one {
            two_t.double()
        } else {
            two_s.square()
        };
        let z3 = &four_s_squared.double() * &s;
        self.with_coords(Coords::Homogeneous {
            x: x3,
            y: y3,
            z: z3,
        })
    }

    fn twice_jacobian(
        &self,
        x: &FpFieldElement<'a>,
        y: &FpFieldElement<'a>,
        z: &FpFieldElement<'a>,
    ) -> Self {
        let z_is_one = z.is_one();
        let y_squared = y.square();
        let t = y_squared.square();
        let a = self.curve.a();
        let a_is_minus_three = -a == three(&self.curve.field().one());

        let (m, s) = if a_is_minus_three {
            let z_squared = if z_is_one { z.clone() } else { z.square() };
            let product = &(x + &z_squared) * &(x - &z_squared);
            (three(&product), four(&(&y_squared * x)))
        } else {
            let mut m = three(&x.square());
            if z_is_one {
                m = &m + a;
            } else if !a.is_zero() {
                m = &m + &(&z.square().square() * a);
            }
            (m, four(&(x * &y_squared)))
        };

        let x3 = &m.square() - &s.double();
        let y3 = &(&(&s - &x3) * &m) - &four(&t).double();
        let mut z3 = y.double();
        if !z_is_one {
            z3 = &z3 * z;
        }
        self.jacobian_point(x3, y3, z3, None)
    }

    fn twice_jacobian_modified(&self, calculate_w: bool) -> Self {
        let Some(Coords::JacobianModified { x, y, z, .. }) = &self.coords else {
            unreachable!("only called on finite modified Jacobian points")
        };
        let az4 = self.jacobian_modified_w();
        let m = &three(&x.square()) + &az4;
        let two_y = y.double();
        let two_y_squared = &two_y * y;
        let s = (x * &two_y_squared).double();
        let x3 = &m.square() - &s.double();
        let eight_t = two_y_squared.square().double();
        let y3 = &(&m * &(&s - &x3)) - &eight_t;
        let az4_3 = calculate_w.then(|| (&eight_t * &az4).double());
        let z3 = if z.is_one() { two_y } else { &two_y * z };
        self.with_coords(Coords::JacobianModified {
            x: x3,
            y: y3,
            z: z3,
            az4: az4_3,
        })
    }

    /// `2P + Q`. Panics when the curves differ.
    pub fn twice_plus(&self, rhs: &Self) -> Self {
        self.assert_same_curve(rhs);
        if self == rhs {
            return self.three_times();
        }
        let Some(coords) = &self.coords else {
            return rhs.clone();
        };
        if rhs.is_infinity() {
            return self.twice();
        }
        if coords.y().is_zero() {
            return rhs.clone();
        }
        match coords {
            Coords::Affine { x, y } => self.twice_plus_affine(x, y, rhs),
            Coords::JacobianModified { .. } => &self.twice_jacobian_modified(false) + rhs,
            _ => &self.twice() + rhs,
        }
    }

    fn twice_plus_affine(
        &self,
        x1: &FpFieldElement<'a>,
        y1: &FpFieldElement<'a>,
        rhs: &Self,
    ) -> Self {
        let x2 = rhs.raw_x().expect("finite point");
        let y2 = rhs.raw_y().expect("finite point");
        let dx = x2 - x1;
        let dy = y2 - y1;
        if dx.is_zero() {
            return if dy.is_zero() {
                self.three_times()
            } else {
                self.clone()
            };
        }
        let x = dx.square();
        let y = dy.square();
        let d = &(&x * &(&x1.double() + x2)) - &y;
        if d.is_zero() {
            return Self::infinity(self.curve);
        }
        let inverse = (&d * &dx).invert().expect("the denominator is not zero");
        let l1 = &(&d * &inverse) * &dy;
        let l2 = &(&(&(&y1.double() * &x) * &dx) * &inverse) - &l1;
        let x4 = &(&(&l2 - &l1) * &(&l1 + &l2)) + x2;
        let y4 = &(&l2 * &(x1 - &x4)) - y1;
        Self::new(self.curve, x4, y4)
    }

    /// `3P`.
    pub fn three_times(&self) -> Self {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        if coords.y().is_zero() {
            return self.clone();
        }
        match coords {
            Coords::Affine { x, y } => self.three_times_affine(x, y),
            Coords::JacobianModified { .. } => &self.twice_jacobian_modified(false) + self,
            _ => &self.twice() + self,
        }
    }

    fn three_times_affine(&self, x1: &FpFieldElement<'a>, y1: &FpFieldElement<'a>) -> Self {
        let two_y = y1.double();
        let x = two_y.square();
        let z = &three(&x1.square()) + self.curve.a();
        let y = z.square();
        let d = &(&three(x1) * &x) - &y;
        if d.is_zero() {
            return Self::infinity(self.curve);
        }
        let inverse = (&d * &two_y).invert().expect("the denominator is not zero");
        let l1 = &(&d * &inverse) * &z;
        let l2 = &(&x.square() * &inverse) - &l1;
        let x4 = &(&(&l2 - &l1) * &(&l1 + &l2)) + x1;
        let y4 = &(&l2 * &(x1 - &x4)) - y1;
        Self::new(self.curve, x4, y4)
    }

    /// `2^exponent · P`, in BC's shared modified-Jacobian loop.
    pub fn times_pow2(&self, exponent: usize) -> Self {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        match exponent {
            0 => return self.clone(),
            1 => return self.twice(),
            _ => {}
        }
        if coords.y().is_zero() {
            return Self::infinity(self.curve);
        }

        let mut x = coords.x().clone();
        let mut y = coords.y().clone();
        let mut z = coords
            .z()
            .cloned()
            .unwrap_or_else(|| self.curve.field().one());
        let mut w = self.curve.a().clone();
        if !z.is_one() {
            match coords {
                Coords::Homogeneous { .. } => {
                    let z_squared = z.square();
                    x = &x * &z;
                    y = &y * &z_squared;
                    w = self.calculate_jacobian_modified_w(&z, Some(&z_squared));
                }
                Coords::Jacobian { .. } => w = self.calculate_jacobian_modified_w(&z, None),
                Coords::JacobianModified { .. } => w = self.jacobian_modified_w(),
                Coords::Affine { .. } => unreachable!("affine Z is one"),
            }
        }

        for _ in 0..exponent {
            if y.is_zero() {
                return Self::infinity(self.curve);
            }
            let mut m = three(&x.square());
            let two_y = y.double();
            let two_y_squared = &two_y * &y;
            let s = (&x * &two_y_squared).double();
            let eight_t = two_y_squared.square().double();
            if !w.is_zero() {
                m = &m + &w;
                w = (&eight_t * &w).double();
            }
            x = &m.square() - &s.double();
            y = &(&m * &(&s - &x)) - &eight_t;
            z = if z.is_one() { two_y } else { &two_y * &z };
        }

        match coords {
            Coords::Affine { .. } => {
                let inverse = z.invert().expect("a finite point has a nonzero Z");
                let inverse2 = inverse.square();
                let inverse3 = &inverse2 * &inverse;
                Self::new(self.curve, &x * &inverse2, &y * &inverse3)
            }
            Coords::Homogeneous { .. } => {
                let x = &x * &z;
                let z = &z * &z.square();
                self.with_coords(Coords::Homogeneous { x, y, z })
            }
            Coords::Jacobian { .. } => self.jacobian_point(x, y, z, None),
            Coords::JacobianModified { .. } => self.with_coords(Coords::JacobianModified {
                x,
                y,
                z,
                az4: Some(w),
            }),
        }
    }

    /// The exact length of the SEC 1 encoding.
    pub fn encoded_length(&self, compressed: bool) -> usize {
        if self.is_infinity() {
            1
        } else {
            self.curve.affine_point_encoding_length(compressed)
        }
    }

    /// Writes the SEC 1 encoding into `output`, normalizing once; nothing is written
    /// when `output` is too short.
    pub fn encode_to(
        &self,
        compressed: bool,
        output: &mut [u8],
    ) -> Result<usize, PointEncodeError> {
        let required = self.encoded_length(compressed);
        if output.len() < required {
            return Err(PointEncodeError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        let output = &mut output[..required];
        let normalized = self.normalize();
        let (Some(x), Some(y)) = (normalized.raw_x(), normalized.raw_y()) else {
            output[0] = 0x00;
            return Ok(1);
        };
        let len = self.curve.field_element_encoding_length();
        if compressed {
            output[0] = if y.to_big_uint().bit(0) { 0x03 } else { 0x02 };
            write_field_element(x, &mut output[1..]);
        } else {
            output[0] = 0x04;
            write_field_element(x, &mut output[1..1 + len]);
            write_field_element(y, &mut output[1 + len..]);
        }
        Ok(required)
    }

    /// The SEC 1 encoding.
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let mut output = vec![0; self.encoded_length(compressed)];
        self.encode_to(compressed, &mut output)
            .expect("the buffer has the exact length");
        output
    }

    fn add_point(&self, rhs: &Self) -> Self {
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
                self.add_affine(x1, y1, x2, y2)
            }
            (
                Coords::Homogeneous {
                    x: x1,
                    y: y1,
                    z: z1,
                },
                Coords::Homogeneous {
                    x: x2,
                    y: y2,
                    z: z2,
                },
            ) => self.add_homogeneous([x1, y1, z1], [x2, y2, z2]),
            _ => self.add_jacobian(left, right),
        }
    }

    fn add_affine(
        &self,
        x1: &FpFieldElement<'a>,
        y1: &FpFieldElement<'a>,
        x2: &FpFieldElement<'a>,
        y2: &FpFieldElement<'a>,
    ) -> Self {
        let dx = x2 - x1;
        let dy = y2 - y1;
        if dx.is_zero() {
            return if dy.is_zero() {
                self.twice()
            } else {
                Self::infinity(self.curve)
            };
        }
        let gamma = &dy * &dx.invert().expect("dx is not zero");
        let x3 = &(&gamma.square() - x1) - x2;
        let y3 = &(&gamma * &(x1 - &x3)) - y1;
        Self::new(self.curve, x3, y3)
    }

    fn add_homogeneous(
        &self,
        [x1, y1, z1]: [&FpFieldElement<'a>; 3],
        [x2, y2, z2]: [&FpFieldElement<'a>; 3],
    ) -> Self {
        let z1_is_one = z1.is_one();
        let z2_is_one = z2.is_one();
        let u1 = if z1_is_one { y2.clone() } else { y2 * z1 };
        let u2 = if z2_is_one { y1.clone() } else { y1 * z2 };
        let u = &u1 - &u2;
        let v1 = if z1_is_one { x2.clone() } else { x2 * z1 };
        let v2 = if z2_is_one { x1.clone() } else { x1 * z2 };
        let v = &v1 - &v2;
        if v.is_zero() {
            return if u.is_zero() {
                self.twice()
            } else {
                Self::infinity(self.curve)
            };
        }
        let w = if z1_is_one {
            z2.clone()
        } else if z2_is_one {
            z1.clone()
        } else {
            z1 * z2
        };
        let v_squared = v.square();
        let v_cubed = &v_squared * &v;
        let v_squared_v2 = &v_squared * &v2;
        let a = &(&(&u.square() * &w) - &v_cubed) - &v_squared_v2.double();
        let x3 = &v * &a;
        let y3 = &(&(&v_squared_v2 - &a) * &u) - &(&u2 * &v_cubed);
        let z3 = &v_cubed * &w;
        self.with_coords(Coords::Homogeneous {
            x: x3,
            y: y3,
            z: z3,
        })
    }

    fn add_jacobian(&self, left: &Coords<'a>, right: &Coords<'a>) -> Self {
        let (x1, y1, z1) = (
            left.x(),
            left.y(),
            left.z().expect("a Jacobian point has Z"),
        );
        let (x2, y2, z2) = (
            right.x(),
            right.y(),
            right.z().expect("a Jacobian point has Z"),
        );
        let z1_is_one = z1.is_one();

        if !z1_is_one && z1 == z2 {
            let dx = x1 - x2;
            let dy = y1 - y2;
            if dx.is_zero() {
                return if dy.is_zero() {
                    self.twice()
                } else {
                    Self::infinity(self.curve)
                };
            }
            let c = dx.square();
            let w1 = x1 * &c;
            let w2 = x2 * &c;
            let a1 = &(&w1 - &w2) * y1;
            let x3 = &(&dy.square() - &w1) - &w2;
            let y3 = &(&(&w1 - &x3) * &dy) - &a1;
            let z3 = &dx * z1;
            return self.jacobian_point(x3, y3, z3, None);
        }

        let (u2, s2) = if z1_is_one {
            (x2.clone(), y2.clone())
        } else {
            let z1_squared = z1.square();
            let z1_cubed = &z1_squared * z1;
            (&z1_squared * x2, &z1_cubed * y2)
        };
        let z2_is_one = z2.is_one();
        let (u1, s1) = if z2_is_one {
            (x1.clone(), y1.clone())
        } else {
            let z2_squared = z2.square();
            let z2_cubed = &z2_squared * z2;
            (&z2_squared * x1, &z2_cubed * y1)
        };
        let h = &u1 - &u2;
        let r = &s1 - &s2;
        if h.is_zero() {
            return if r.is_zero() {
                self.twice()
            } else {
                Self::infinity(self.curve)
            };
        }
        let h_squared = h.square();
        let g = &h_squared * &h;
        let v = &h_squared * &u1;
        let x3 = &(&r.square() + &g) - &v.double();
        let y3 = &(&(&v - &x3) * &r) - &(&g * &s1);
        let mut z3 = h;
        if !z1_is_one {
            z3 = &z3 * z1;
        }
        if !z2_is_one {
            z3 = &z3 * z2;
        }
        let z3_squared = (z1_is_one && z2_is_one).then_some(h_squared);
        self.jacobian_point(x3, y3, z3, z3_squared.as_ref())
    }

    fn jacobian_point(
        &self,
        x: FpFieldElement<'a>,
        y: FpFieldElement<'a>,
        z: FpFieldElement<'a>,
        z_squared: Option<&FpFieldElement<'a>>,
    ) -> Self {
        let coords = match self.curve.coordinate_system() {
            CoordinateSystem::Jacobian => Coords::Jacobian { x, y, z },
            CoordinateSystem::JacobianModified => {
                let az4 = Some(self.calculate_jacobian_modified_w(&z, z_squared));
                Coords::JacobianModified { x, y, z, az4 }
            }
            _ => unreachable!("only Jacobian systems come here"),
        };
        self.with_coords(coords)
    }

    fn calculate_jacobian_modified_w(
        &self,
        z: &FpFieldElement<'a>,
        z_squared: Option<&FpFieldElement<'a>>,
    ) -> FpFieldElement<'a> {
        let a = self.curve.a();
        if a.is_zero() || z.is_one() {
            return a.clone();
        }
        let z_squared = z_squared.cloned().unwrap_or_else(|| z.square());
        a * &z_squared.square()
    }

    fn jacobian_modified_w(&self) -> FpFieldElement<'a> {
        let Some(Coords::JacobianModified { z, az4, .. }) = &self.coords else {
            unreachable!("only called on finite modified Jacobian points")
        };
        az4.clone()
            .unwrap_or_else(|| self.calculate_jacobian_modified_w(z, None))
    }

    fn assert_same_curve(&self, rhs: &Self) {
        assert!(
            (core::ptr::eq(self.curve, rhs.curve) || self.curve == rhs.curve)
                && self.curve.coordinate_system() == rhs.curve.coordinate_system(),
            "points on different curves or coordinate systems"
        );
    }
}

fn three<'a>(value: &FpFieldElement<'a>) -> FpFieldElement<'a> {
    &value.double() + value
}

fn four<'a>(value: &FpFieldElement<'a>) -> FpFieldElement<'a> {
    value.double().double()
}

fn scale_by_z<'a>(
    value: &FpFieldElement<'a>,
    z: Option<&FpFieldElement<'a>>,
    power: u32,
) -> FpFieldElement<'a> {
    match z {
        Some(z) if power != 0 && !z.is_one() => {
            let scale = match power {
                1 => z.clone(),
                2 => z.square(),
                _ => &z.square() * z,
            };
            value * &scale
        }
        _ => value.clone(),
    }
}

fn write_field_element(value: &FpFieldElement<'_>, output: &mut [u8]) {
    let bytes = ArrayEncoding::<u8>::to_be(&value.to_big_uint());
    let (padding, digits) = bytes.split_at(bytes.len() - output.len());
    debug_assert!(padding.iter().all(|&byte| byte == 0));
    output.copy_from_slice(digits);
}

/// `P + Q`. Panics when the curves or coordinate systems differ.
impl<'a> Add for &FpPoint<'a> {
    type Output = FpPoint<'a>;

    fn add(self, rhs: Self) -> FpPoint<'a> {
        self.add_point(rhs)
    }
}

/// `P - Q`. Panics when the curves or coordinate systems differ.
impl<'a> Sub for &FpPoint<'a> {
    type Output = FpPoint<'a>;

    fn sub(self, rhs: Self) -> FpPoint<'a> {
        self.add_point(&-rhs)
    }
}

/// `-P`.
impl<'a> Neg for &FpPoint<'a> {
    type Output = FpPoint<'a>;

    fn neg(self) -> FpPoint<'a> {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        let coords = match coords {
            Coords::Affine { x, y } => Coords::Affine {
                x: x.clone(),
                y: -y,
            },
            Coords::Homogeneous { x, y, z } => Coords::Homogeneous {
                x: x.clone(),
                y: -y,
                z: z.clone(),
            },
            Coords::Jacobian { x, y, z } => Coords::Jacobian {
                x: x.clone(),
                y: -y,
                z: z.clone(),
            },
            Coords::JacobianModified { x, y, z, az4 } => Coords::JacobianModified {
                x: x.clone(),
                y: -y,
                z: z.clone(),
                az4: az4.clone(),
            },
        };
        self.with_coords(coords)
    }
}

/// `kP` by double-and-add from the top bit. Variable time; only for a public scalar.
impl<'a> Mul<&PaddedBigUint> for &FpPoint<'a> {
    type Output = FpPoint<'a>;

    fn mul(self, scalar: &PaddedBigUint) -> FpPoint<'a> {
        let mut result = FpPoint::infinity(self.curve);
        for bit in (0..scalar.bits()).rev() {
            result = result.twice();
            if scalar.bit(bit) {
                result = result.add_point(self);
            }
        }
        result
    }
}

/// The same point on the same curve, whatever the projective scale.
impl PartialEq for FpPoint<'_> {
    fn eq(&self, other: &Self) -> bool {
        if !(core::ptr::eq(self.curve, other.curve) || self.curve == other.curve) {
            return false;
        }
        let (Some(left), Some(right)) = (&self.coords, &other.coords) else {
            return self.is_infinity() && other.is_infinity();
        };
        let (left_x_power, left_y_power) = left.powers();
        let (right_x_power, right_y_power) = right.powers();
        scale_by_z(left.x(), right.z(), right_x_power)
            == scale_by_z(right.x(), left.z(), left_x_power)
            && scale_by_z(left.y(), right.z(), right_y_power)
                == scale_by_z(right.y(), left.z(), left_y_power)
    }
}

impl Eq for FpPoint<'_> {}

/// Prints only whether the point is at infinity, never the coordinates.
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
    use tc_ec_core_v2::{CoordinateSystem, PointDecodeError, PointEncodeError};

    use crate::{FpCurve, FpField, FpPoint};

    const SYSTEMS: [CoordinateSystem; 4] = [
        CoordinateSystem::Affine,
        CoordinateSystem::Homogeneous,
        CoordinateSystem::Jacobian,
        CoordinateSystem::JacobianModified,
    ];

    fn int(value: u8) -> PaddedBigUint {
        PaddedBigUint::from(value)
    }

    // y² = x³ + 2x + 2 over F17, of prime order 19, generated by (5, 1).
    fn curve17(field: &FpField, system: CoordinateSystem) -> FpCurve<'_> {
        FpCurve::new(field, &int(2), &int(2), Some(int(19)), Some(int(1)))
            .with_coordinate_system(system)
    }

    fn coordinates(point: &FpPoint<'_>) -> (PaddedBigUint, PaddedBigUint) {
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
    }

    #[test]
    fn every_coordinate_system_agrees_with_the_known_multiples() {
        let field = FpField::new(int(17));
        for system in SYSTEMS {
            let curve = curve17(&field, system);
            let g = curve.create_point(&int(5), &int(1));
            assert_eq!(coordinates(&g.twice()), (int(6), int(3)), "{system:?}");
            assert_eq!(
                coordinates(&(&g + &g.twice())),
                (int(10), int(6)),
                "{system:?}"
            );
            assert_eq!(g.three_times(), &g + &g.twice(), "{system:?}");
            assert_eq!(g.twice_plus(&g.twice()), &g * &int(4), "{system:?}");
            assert_eq!(g.times_pow2(3), &g * &int(8), "{system:?}");
            assert_eq!(&(&g * &int(7)) - &g, &g * &int(6), "{system:?}");
            assert!((&g * &int(19)).is_infinity(), "{system:?}");
            assert!((&g + &-&g).is_infinity(), "{system:?}");
        }
    }

    #[test]
    fn every_multiple_stays_on_the_curve_and_is_valid() {
        let field = FpField::new(int(17));
        for system in SYSTEMS {
            let curve = curve17(&field, system);
            let g = curve.create_point(&int(5), &int(1));
            for k in 0..19 {
                let p = &g * &int(k);
                assert!(p.is_on_curve() && p.is_valid(), "{system:?}, k = {k}");
                assert!(p.normalize().is_normalized(), "{system:?}, k = {k}");
            }
            assert!(
                !curve.create_point(&int(5), &int(2)).is_on_curve(),
                "{system:?}"
            );
        }
    }

    #[test]
    fn encodings_round_trip_in_every_form() {
        let field = FpField::new(int(17));
        for system in SYSTEMS {
            let curve = curve17(&field, system);
            let g = curve.create_point(&int(5), &int(1));
            for k in 0..19 {
                let p = &g * &int(k);
                for compressed in [false, true] {
                    let encoded = p.encode(compressed);
                    assert_eq!(encoded.len(), p.encoded_length(compressed));
                    assert_eq!(
                        curve.decode_point(&encoded),
                        Ok(p.clone()),
                        "{system:?}, k = {k}"
                    );
                }
            }
        }
    }

    #[test]
    fn known_encodings_and_malformed_inputs_decode_as_in_sec1() {
        let field = FpField::new(int(17));
        let curve = curve17(&field, CoordinateSystem::Affine);
        let g = curve.create_point(&int(5), &int(1));
        assert_eq!(g.encode(false), [0x04, 5, 1]);
        assert_eq!(g.encode(true), [0x03, 5]);
        assert_eq!(curve.infinity().encode(true), [0x00]);
        assert_eq!(curve.decode_point(&[0x07, 5, 1]), Ok(g.clone()));
        assert_eq!(curve.decode_point(&[]), Err(PointDecodeError::Empty));
        assert_eq!(
            curve.decode_point(&[0x04, 5]),
            Err(PointDecodeError::InvalidLength)
        );
        assert_eq!(
            curve.decode_point(&[0x05, 5]),
            Err(PointDecodeError::UnknownEncoding(5))
        );
        assert_eq!(
            curve.decode_point(&[0x04, 17, 1]),
            Err(PointDecodeError::CoordinateOutOfRange)
        );
        assert_eq!(
            curve.decode_point(&[0x06, 5, 1]),
            Err(PointDecodeError::InconsistentHybridY)
        );
        assert_eq!(
            curve.decode_point(&[0x04, 5, 2]),
            Err(PointDecodeError::NotOnCurve)
        );
        assert_eq!(
            g.encode_to(false, &mut [0; 2]),
            Err(PointEncodeError::OutputTooShort {
                required: 3,
                available: 2
            })
        );
    }

    fn hex(text: &str) -> PaddedBigUint {
        let bytes: alloc::vec::Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect();
        <PaddedBigUint as tc_bigint::ArrayEncoding<u8>>::from_be(&bytes).unwrap()
    }

    #[test]
    fn p256_doubles_to_the_nist_vector_and_its_order_annihilates_the_generator() {
        let p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        let a = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
        let b = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
        let gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        let gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        let n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
        let x2 = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
        let y2 = "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";

        let field = FpField::new(hex(p));
        for system in SYSTEMS {
            let curve = FpCurve::new(&field, &hex(a), &hex(b), Some(hex(n)), Some(int(1)))
                .with_coordinate_system(system);
            let g = curve.create_point(&hex(gx), &hex(gy));
            assert!(g.is_on_curve(), "{system:?}");
            assert_eq!(coordinates(&g.twice()), (hex(x2), hex(y2)), "{system:?}");
            assert!((&g * &hex(n)).is_infinity(), "{system:?}");

            let encoded = g.twice().encode(true);
            assert_eq!(encoded.len(), 33);
            assert_eq!(curve.decode_point(&encoded), Ok(g.twice()), "{system:?}");
        }
    }
}
