use crate::SecTCtCurve;
use crate::sec1;
use crate::sect_element::SecTElement;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use tc_bigint::{PaddedBigUint, Word};
use tc_constant_time::Choice;
use tc_ec_core_v2::{Curve, Point, PointEncodeError};

/// A point of a [`SecTCtCurve`] in affine coordinates, `None` for infinity. Only
/// [`multiply`](Self::multiply) is constant time; the group operations of [`Point`] are BC's
/// affine formulas, variable time and only for public points.
#[derive(Clone)]
pub struct SecTCtPoint<'a, F> {
    curve: &'a SecTCtCurve<F>,
    xy: Option<(F, F)>,
}

impl<'a, F: SecTElement> SecTCtPoint<'a, F> {
    pub(crate) fn new(curve: &'a SecTCtCurve<F>, x: F, y: F) -> Self {
        Self {
            curve,
            xy: Some((x, y)),
        }
    }

    pub(crate) fn infinity(curve: &'a SecTCtCurve<F>) -> Self {
        Self { curve, xy: None }
    }

    /// `y² + xy = x³ + ax² + b`; infinity counts as on the curve. Constant time; only the
    /// answer is revealed.
    pub fn is_on_curve(&self) -> bool {
        let Some((x, y)) = &self.xy else {
            return true;
        };
        let (a, b) = (self.curve.a(), self.curve.b());
        y.add(x).multiply(y) == x.add(a).multiply(&x.square()).add(b)
    }

    // With cofactor 2, a point of odd order has Tr(x) = 1.
    fn satisfies_order(&self) -> bool {
        let Some((x, _)) = &self.xy else {
            return true;
        };
        let cofactor = self.curve.cofactor().expect("a SEC curve has a cofactor");
        if *cofactor == PaddedBigUint::from(2u8) {
            return x.trace() != 0;
        }
        let n = self.curve.order().expect("a SEC curve has an order");
        self.multiply(n).is_infinity()
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

    /// Writes the SEC 1 encoding into `output`; nothing is written when `output` is
    /// too short. Constant time apart from whether
    /// this is infinity.
    pub fn encode_to(
        &self,
        compressed: bool,
        output: &mut [u8],
    ) -> Result<usize, PointEncodeError> {
        sec1::encode(self.xy.as_ref(), compressed, output)
    }

    /// The SEC 1 encoding. Constant time apart from whether
    /// this is infinity.
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let mut output = vec![0; self.encoded_length(compressed)];
        self.encode_to(compressed, &mut output)
            .expect("the buffer has the exact length");
        output
    }

    fn assert_same_curve(&self, rhs: &Self) {
        assert!(
            core::ptr::eq(self.curve, rhs.curve) || self.curve == rhs.curve,
            "points on different curves"
        );
    }

    /// `kP` by the Montgomery ladder of López and Dahab (1999) over the public width of
    /// `scalar`: x-only projective steps behind conditional swaps, then one inversion to
    /// recover `y`. Constant time in the scalar and in the coordinates, as far as the field
    /// is; only whether the result is infinity, as it is for `k ≡ 0 (mod n)`, is revealed.
    /// A point with `x = 0` has order 2, outside every prime-order subgroup; there the
    /// result, the point or infinity, gives away the parity of `k`.
    pub fn multiply(&self, scalar: &PaddedBigUint) -> Self {
        let Some((x, y)) = &self.xy else {
            return self.clone();
        };
        if x.is_zero() {
            return if scalar.bit(0) {
                self.clone()
            } else {
                Self::infinity(self.curve)
            };
        }

        let b = self.curve.b();
        // (x0 : z0) and (x1 : z1) are kP and (k + 1)P for the bits read so far.
        let (mut x0, mut z0) = (F::one(), F::zero());
        let (mut x1, mut z1) = (x.clone(), F::one());
        let width = scalar.as_limbs().len() as u32 * Word::BITS;
        for i in (0..width).rev() {
            let bit = Choice::from_lsb(u8::from(scalar.bit(i)));
            F::conditional_swap(&mut x0, &mut x1, bit);
            F::conditional_swap(&mut z0, &mut z1, bit);
            // The sum, whose difference is ±P, then the double.
            let (t0, t1) = (x0.multiply(&z1), x1.multiply(&z0));
            z1 = t0.add(&t1).square();
            x1 = x.multiply(&z1).add(&t0.multiply(&t1));
            let (xx, zz) = (x0.square(), z0.square());
            x0 = xx.square().add(&b.multiply(&zz.square()));
            z0 = xx.multiply(&zz);
            F::conditional_swap(&mut x0, &mut x1, bit);
            F::conditional_swap(&mut z0, &mut z1, bit);
        }
        self.recover_y(x, y, [&x0, &z0], [&x1, &z1])
    }

    // López and Dahab's Mxy: the affine kP from P, kP and (k + 1)P, with 1/z0 taken from
    // the one inversion. Where (k + 1)P is infinity, kP is -P = (x, x + y).
    fn recover_y(&self, x: &F, y: &F, [x0, z0]: [&F; 2], [x1, z1]: [&F; 2]) -> Self {
        let z0z1 = z0.multiply(z1);
        let inverse = x.multiply(&z0z1).invert_or_zero();
        let xk = x0.multiply(&x.multiply(z1).multiply(&inverse));
        let sum = x0
            .add(&x.multiply(z0))
            .multiply(&x1.add(&x.multiply(z1)))
            .add(&x.square().add(y).multiply(&z0z1));
        let yk = x.add(&xk).multiply(&sum).multiply(&inverse).add(y);

        let minus_p = z1.ct_eq(&F::zero());
        let xk = F::conditional_select(&xk, x, minus_p);
        let yk = F::conditional_select(&yk, &x.add(y), minus_p);
        if z0.is_zero() {
            Self::infinity(self.curve)
        } else {
            Self::new(self.curve, xk, yk)
        }
    }
}

fn divide<F: SecTElement>(x: &F, y: &F) -> F {
    x.multiply(&y.invert().expect("the divisor is not zero"))
}

impl<'a, F: SecTElement> Point for SecTCtPoint<'a, F> {
    type Curve = &'a SecTCtCurve<F>;

    fn curve(&self) -> &'a SecTCtCurve<F> {
        self.curve
    }

    fn is_valid(&self) -> bool {
        self.is_on_curve() && self.satisfies_order()
    }

    fn infinity(&self) -> Self {
        Self::infinity(self.curve)
    }

    fn is_infinity(&self) -> bool {
        self.xy.is_none()
    }

    fn x(&self) -> Option<F> {
        self.xy.as_ref().map(|(x, _)| x.clone())
    }

    fn y(&self) -> Option<F> {
        self.xy.as_ref().map(|(_, y)| y.clone())
    }

    /// BC's affine `F2mPoint.Add`. Variable time.
    fn add(&self, rhs: &Self) -> Self {
        self.assert_same_curve(rhs);
        let (Some((x1, y1)), Some((x2, y2))) = (&self.xy, &rhs.xy) else {
            return if self.is_infinity() {
                rhs.clone()
            } else {
                self.clone()
            };
        };
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

    /// BC's affine `F2mPoint.Twice`. Variable time.
    fn twice(&self) -> Self {
        let Some((x1, y1)) = &self.xy else {
            return self.clone();
        };
        if x1.is_zero() {
            // A point with x = 0 is its own negative.
            return Self::infinity(self.curve);
        }
        let l1 = divide(y1, x1).add(x1);
        let x3 = l1.square().add(&l1).add(self.curve.a());
        let y3 = x1.square().add(&x3.multiply(&l1.add(&F::one())));
        Self::new(self.curve, x3, y3)
    }

    /// `(x, x + y)`. Constant time apart from whether this is infinity.
    fn negate(&self) -> Self {
        let Some((x, y)) = &self.xy else {
            return self.clone();
        };
        Self::new(self.curve, x.clone(), y.add(x))
    }

    fn normalize(&self) -> Self {
        self.clone()
    }

    fn projective_z(&self) -> Option<F> {
        None
    }

    fn normalize_with_inverse(&self, _inverse: &F) -> Self {
        self.clone()
    }
}

/// The same point on the same curve. Constant time in the coordinates.
impl<F: SecTElement> PartialEq for SecTCtPoint<'_, F> {
    fn eq(&self, other: &Self) -> bool {
        (core::ptr::eq(self.curve, other.curve) || self.curve == other.curve) && self.xy == other.xy
    }
}

impl<F: SecTElement> Eq for SecTCtPoint<'_, F> {}

/// Prints only whether the point is at infinity, never the coordinates.
impl<F> fmt::Debug for SecTCtPoint<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecTCtPoint")
            .field("infinity", &self.xy.is_none())
            .finish_non_exhaustive()
    }
}
