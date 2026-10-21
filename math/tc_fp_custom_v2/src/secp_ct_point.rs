use crate::secp_element::SecPElement;
use crate::{SecPCtCurve, sec1};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use tc_bigint::{PaddedBigUint, Word};
use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
use tc_ec_core_v2::{Curve, Point, PointEncodeError};

const WINDOW: u32 = 4;

/// A point of a [`SecPCtCurve`], in homogeneous coordinates (X : Y : Z) for the complete
/// formulas, with infinity as (0 : 1 : 0).
///
/// Every operation takes the same field operations whatever the coordinates and the
/// scalar, so a point and a scalar may be secret. Where a method returns a `bool` or an
/// `Option`, that answer alone is revealed.
#[derive(Clone)]
pub struct SecPCtPoint<'a, F> {
    curve: &'a SecPCtCurve<F>,
    x: F,
    y: F,
    z: F,
}

impl<'a, F: SecPElement> SecPCtPoint<'a, F> {
    pub(crate) fn new(curve: &'a SecPCtCurve<F>, x: F, y: F) -> Self {
        Self {
            curve,
            x,
            y,
            z: F::one(),
        }
    }

    pub(crate) fn infinity(curve: &'a SecPCtCurve<F>) -> Self {
        Self {
            curve,
            x: F::zero(),
            y: F::one(),
            z: F::zero(),
        }
    }

    /// The affine `(x, y)`, or `None` at infinity, at the cost of one inversion. Constant
    /// time apart from whether this is infinity.
    pub fn affine(&self) -> Option<(F, F)> {
        let inverse = self.z.invert()?;
        Some((self.x.multiply(&inverse), self.y.multiply(&inverse)))
    }

    /// Whether `Y²Z = X³ + aXZ² + bZ³`; infinity counts as on the curve. The subgroup is
    /// not checked; see [`is_valid`](Point::is_valid). Constant time; only the answer is
    /// revealed.
    pub fn is_on_curve(&self) -> bool {
        let (x, y, z) = (&self.x, &self.y, &self.z);
        let z2 = z.square();
        let lhs = y.square().multiply(z);
        let rhs = x
            .square()
            .multiply(x)
            .add(&self.curve.a().multiply(x).multiply(&z2))
            .add(&self.curve.b().multiply(&z2.multiply(z)));
        lhs == rhs
    }

    /// `P - Q`. Constant time. Panics when the curves differ.
    pub fn subtract(&self, rhs: &Self) -> Self {
        self.add(&rhs.negate())
    }

    /// `kP` over every window of the width of `scalar`, which is public, with a lookup
    /// that reads the whole table. Constant time in the point and the scalar.
    pub fn multiply(&self, scalar: &PaddedBigUint) -> Self {
        Self::multiply_window(&self.window_table(), scalar)
    }

    // 0P to 15P, the table of the fixed window. Constant time.
    pub(crate) fn window_table(&self) -> Vec<Self> {
        let mut table = Vec::with_capacity(1 << WINDOW);
        table.push(Self::infinity(self.curve));
        for i in 1..1 << WINDOW {
            let next = table[i - 1].add(self);
            table.push(next);
        }
        table
    }

    // kP over every window of the width of `scalar` on P's `window_table`. Constant time.
    pub(crate) fn multiply_window(table: &[Self], scalar: &PaddedBigUint) -> Self {
        let width = scalar.as_limbs().len() as u32 * Word::BITS;
        let mut result = table[0].clone();
        for window in (0..width / WINDOW).rev() {
            for _ in 0..WINDOW {
                result = result.twice();
            }
            let mut index = 0u8;
            for bit in (0..WINDOW).rev() {
                index = (index << 1) | u8::from(scalar.bit(window * WINDOW + bit));
            }
            result = result.add(&lookup(table, index));
        }
        result
    }

    /// The exact length of the SEC 1 encoding. Constant time apart from whether this is
    /// infinity.
    pub fn encoded_length(&self, compressed: bool) -> usize {
        if self.is_infinity() {
            1
        } else {
            self.curve.affine_point_encoding_length(compressed)
        }
    }

    /// Writes the SEC 1 encoding into `output`; nothing is written when `output` is too
    /// short. Constant time apart from whether this is infinity.
    pub fn encode_to(
        &self,
        compressed: bool,
        output: &mut [u8],
    ) -> Result<usize, PointEncodeError> {
        sec1::encode(self.affine().as_ref(), compressed, output)
    }

    /// The SEC 1 encoding. Constant time apart from whether this is infinity.
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let mut output = vec![0; self.encoded_length(compressed)];
        self.encode_to(compressed, &mut output)
            .expect("the buffer has the exact length");
        output
    }

    fn with(&self, x: F, y: F, z: F) -> Self {
        Self {
            curve: self.curve,
            x,
            y,
            z,
        }
    }

    fn assert_same_curve(&self, rhs: &Self) {
        assert!(
            core::ptr::eq(self.curve, rhs.curve) || self.curve == rhs.curve,
            "points on different curves"
        );
    }
}

fn lookup<'a, F: SecPElement>(table: &[SecPCtPoint<'a, F>], index: u8) -> SecPCtPoint<'a, F> {
    let mut selected = table[0].clone();
    for (i, entry) in (0u8..).zip(table).skip(1) {
        selected = SecPCtPoint::conditional_select(&selected, entry, i.ct_eq(&index));
    }
    selected
}

fn double<F: SecPElement>(x: &F) -> F {
    x.add(x)
}

/// `twice_plus`, `three_times` and `times_pow2` take the default loops over public
/// counts. Constant time, apart from the `bool` and `Option` answers.
impl<'a, F: SecPElement> Point for SecPCtPoint<'a, F> {
    type Curve = &'a SecPCtCurve<F>;

    fn curve(&self) -> &'a SecPCtCurve<F> {
        self.curve
    }

    /// On the curve and, when the cofactor is not one, `nP = O`. Constant time; only the
    /// answer is revealed.
    fn is_valid(&self) -> bool {
        let curve = self.curve;
        self.is_on_curve()
            && (*curve.cofactor().expect("a SEC curve has a cofactor") == PaddedBigUint::from(1u8)
                || self
                    .multiply(curve.order().expect("a SEC curve has an order"))
                    .is_infinity())
    }

    fn infinity(&self) -> Self {
        Self::infinity(self.curve)
    }

    /// Whether this is infinity. Constant time; only the answer is revealed.
    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// The affine x. Constant time apart from whether this is infinity.
    fn x(&self) -> Option<F> {
        self.affine().map(|(x, _)| x)
    }

    /// The affine y. Constant time apart from whether this is infinity.
    fn y(&self) -> Option<F> {
        self.affine().map(|(_, y)| y)
    }

    /// `P + Q`, by Algorithm 1 of Renes, Costello and Batina. Constant time. Panics when
    /// the curves differ.
    fn add(&self, rhs: &Self) -> Self {
        self.assert_same_curve(rhs);
        let (a, b3) = (self.curve.a(), self.curve.b3());
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let (x2, y2, z2) = (&rhs.x, &rhs.y, &rhs.z);
        let t0 = x1.multiply(x2);
        let t1 = y1.multiply(y2);
        let t2 = z1.multiply(z2);
        let t3 = x1.add(y1).multiply(&x2.add(y2)).subtract(&t0.add(&t1));
        let t4 = x1.add(z1).multiply(&x2.add(z2)).subtract(&t0.add(&t2));
        let t5 = y1.add(z1).multiply(&y2.add(z2)).subtract(&t1.add(&t2));
        let z3 = a.multiply(&t4).add(&b3.multiply(&t2));
        let x3 = t1.subtract(&z3);
        let z3 = t1.add(&z3);
        let y3 = x3.multiply(&z3);
        let t1 = double(&t0).add(&t0).add(&a.multiply(&t2));
        let t2 = a.multiply(&t0.subtract(&a.multiply(&t2)));
        let t4 = b3.multiply(&t4).add(&t2);
        let y3 = y3.add(&t1.multiply(&t4));
        let x3 = t3.multiply(&x3).subtract(&t5.multiply(&t4));
        let z3 = t5.multiply(&z3).add(&t3.multiply(&t1));
        self.with(x3, y3, z3)
    }

    /// `2P`, by Algorithm 3 of Renes, Costello and Batina. Constant time.
    fn twice(&self) -> Self {
        let (a, b3) = (self.curve.a(), self.curve.b3());
        let (x, y, z) = (&self.x, &self.y, &self.z);
        let t0 = x.square();
        let t1 = y.square();
        let t2 = z.square();
        let t3 = double(&x.multiply(y));
        let z3 = double(&x.multiply(z));
        let x3 = a.multiply(&z3);
        let y3 = x3.add(&b3.multiply(&t2));
        let x3 = t1.subtract(&y3);
        let y3 = t1.add(&y3);
        let y3 = x3.multiply(&y3);
        let x3 = t3.multiply(&x3);
        let z3 = b3.multiply(&z3);
        let t2 = a.multiply(&t2);
        let t3 = a.multiply(&t0.subtract(&t2)).add(&z3);
        let t0 = double(&t0).add(&t0).add(&t2);
        let y3 = y3.add(&t0.multiply(&t3));
        let t2 = double(&y.multiply(z));
        let x3 = x3.subtract(&t2.multiply(&t3));
        let z3 = double(&double(&t2.multiply(&t1)));
        self.with(x3, y3, z3)
    }

    /// `-P`. Constant time.
    fn negate(&self) -> Self {
        self.with(self.x.clone(), self.y.negate(), self.z.clone())
    }

    fn normalize(&self) -> Self {
        match self.affine() {
            Some((x, y)) => Self::new(self.curve, x, y),
            None => self.clone(),
        }
    }

    fn projective_z(&self) -> Option<F> {
        (!self.is_infinity()).then(|| self.z.clone())
    }

    fn normalize_with_inverse(&self, inverse: &F) -> Self {
        self.with(
            self.x.multiply(inverse),
            self.y.multiply(inverse),
            self.z.multiply(inverse),
        )
    }
}

/// `a` or `b`, as the choice says. Constant time. Panics when the curves differ.
impl<F: SecPElement> ConditionallySelectable for SecPCtPoint<'_, F> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        a.assert_same_curve(b);
        a.with(
            F::conditional_select(&a.x, &b.x, choice),
            F::conditional_select(&a.y, &b.y, choice),
            F::conditional_select(&a.z, &b.z, choice),
        )
    }
}

/// The same point whatever the projective scale: `X₁Z₂ = X₂Z₁` and `Y₁Z₂ = Y₂Z₁`.
/// Constant time. Panics when the curves differ.
impl<F: SecPElement> ConstantTimeEq for SecPCtPoint<'_, F> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.assert_same_curve(rhs);
        self.x.multiply(&rhs.z).ct_eq(&rhs.x.multiply(&self.z))
            & self.y.multiply(&rhs.z).ct_eq(&rhs.y.multiply(&self.z))
    }
}

/// Through `ct_eq`; points on different curves are not equal. Constant time; only the
/// answer is revealed.
impl<F: SecPElement> PartialEq for SecPCtPoint<'_, F> {
    fn eq(&self, other: &Self) -> bool {
        (core::ptr::eq(self.curve, other.curve) || self.curve == other.curve)
            && self.ct_eq(other).unwrap_u8() == 1
    }
}

impl<F: SecPElement> Eq for SecPCtPoint<'_, F> {}

/// Prints nothing of the point, which may be secret.
impl<F> fmt::Debug for SecPCtPoint<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecPCtPoint").finish_non_exhaustive()
    }
}
