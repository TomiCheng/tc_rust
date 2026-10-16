use crate::{F2mCtCurve, F2mFieldElement, sec1};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use tc_bigint::{PaddedBigUint, Word};
use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
use tc_ec_core_v2::{BinaryFieldElement, FieldElement, Point, PointEncodeError};

/// A point on an [`F2mCtCurve`] in affine coordinates, `None` for infinity. Only
/// [`multiply`](Self::multiply) is constant time; the group operations of [`Point`] are
/// BC's affine formulas, variable time and only for public points.
#[derive(Clone)]
pub struct F2mCtPoint<'a> {
    curve: &'a F2mCtCurve,
    coords: Option<(F2mFieldElement, F2mFieldElement)>,
}

impl<'a> F2mCtPoint<'a> {
    pub(crate) fn new(curve: &'a F2mCtCurve, x: F2mFieldElement, y: F2mFieldElement) -> Self {
        Self {
            curve,
            coords: Some((x, y)),
        }
    }

    pub(crate) fn infinity(curve: &'a F2mCtCurve) -> Self {
        Self {
            curve,
            coords: None,
        }
    }

    /// `y² + xy = x³ + ax² + b`; infinity counts as on the curve. Constant time; only the
    /// answer is revealed.
    pub fn is_on_curve(&self) -> bool {
        let Some((x, y)) = &self.coords else {
            return true;
        };
        let (a, b) = (self.curve.a(), self.curve.b());
        y.add(x).multiply(y) == x.add(a).multiply(&x.square()).add(b)
    }

    // As on the Var curve: with cofactor 2, a point of odd order has Tr(x) = 1.
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
            .is_none_or(|n| self.multiply(n).is_infinity())
    }

    pub fn subtract(&self, rhs: &Self) -> Self {
        self.add(&rhs.negate())
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
        sec1::encode(self.curve.field(), self.coords.as_ref(), compressed, output)
    }

    /// The SEC 1 encoding. Constant time apart from whether this is infinity.
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
        let Some((x, y)) = &self.coords else {
            return self.clone();
        };
        if x.is_zero() {
            return if scalar.bit(0) {
                self.clone()
            } else {
                Self::infinity(self.curve)
            };
        }

        let field = self.curve.field();
        let b = self.curve.b();
        // (x0 : z0) and (x1 : z1) are kP and (k + 1)P for the bits read so far.
        let (mut x0, mut z0) = (field.one(), field.zero());
        let (mut x1, mut z1) = (x.clone(), field.one());
        let width = scalar.as_limbs().len() as u32 * Word::BITS;
        for i in (0..width).rev() {
            let bit = Choice::from_lsb(u8::from(scalar.bit(i)));
            F2mFieldElement::conditional_swap(&mut x0, &mut x1, bit);
            F2mFieldElement::conditional_swap(&mut z0, &mut z1, bit);
            // The sum, whose difference is ±P, then the double.
            let (t0, t1) = (x0.multiply(&z1), x1.multiply(&z0));
            z1 = t0.add(&t1).square();
            x1 = x.multiply(&z1).add(&t0.multiply(&t1));
            let (xx, zz) = (x0.square(), z0.square());
            x0 = xx.square().add(&b.multiply(&zz.square()));
            z0 = xx.multiply(&zz);
            F2mFieldElement::conditional_swap(&mut x0, &mut x1, bit);
            F2mFieldElement::conditional_swap(&mut z0, &mut z1, bit);
        }
        self.recover_y(x, y, [&x0, &z0], [&x1, &z1])
    }

    // López and Dahab's Mxy: the affine kP from P, kP and (k + 1)P, with 1/z0 taken from
    // the one inversion. Where (k + 1)P is infinity, kP is -P = (x, x + y).
    fn recover_y(
        &self,
        x: &F2mFieldElement,
        y: &F2mFieldElement,
        [x0, z0]: [&F2mFieldElement; 2],
        [x1, z1]: [&F2mFieldElement; 2],
    ) -> Self {
        let z0z1 = z0.multiply(z1);
        let inverse = x.multiply(&z0z1).invert_or_zero();
        let xk = x0.multiply(&x.multiply(z1).multiply(&inverse));
        let sum = x0
            .add(&x.multiply(z0))
            .multiply(&x1.add(&x.multiply(z1)))
            .add(&x.square().add(y).multiply(&z0z1));
        let yk = x.add(&xk).multiply(&sum).multiply(&inverse).add(y);

        let minus_p = z1.ct_eq(&self.curve.field().zero());
        let xk = F2mFieldElement::conditional_select(&xk, x, minus_p);
        let yk = F2mFieldElement::conditional_select(&yk, &x.add(y), minus_p);
        if z0.is_zero() {
            Self::infinity(self.curve)
        } else {
            Self::new(self.curve, xk, yk)
        }
    }
}

fn divide(x: &F2mFieldElement, y: &F2mFieldElement) -> F2mFieldElement {
    x.multiply(&y.invert().expect("the divisor is not zero"))
}

impl<'a> Point for F2mCtPoint<'a> {
    type Curve = &'a F2mCtCurve;

    fn curve(&self) -> &'a F2mCtCurve {
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
        self.coords.as_ref().map(|(x, _)| x.clone())
    }

    fn y(&self) -> Option<F2mFieldElement> {
        self.coords.as_ref().map(|(_, y)| y.clone())
    }

    /// BC's affine `F2mPoint.Add`. Variable time.
    fn add(&self, rhs: &Self) -> Self {
        self.assert_same_curve(rhs);
        let (Some((x1, y1)), Some((x2, y2))) = (&self.coords, &rhs.coords) else {
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
        let Some((x1, y1)) = &self.coords else {
            return self.clone();
        };
        if x1.is_zero() {
            // A point with x = 0 is its own negative.
            return Self::infinity(self.curve);
        }
        let l1 = divide(y1, x1).add(x1);
        let x3 = l1.square().add(&l1).add(self.curve.a());
        let one = self.curve.field().one();
        let y3 = x1.square().add(&x3.multiply(&l1.add(&one)));
        Self::new(self.curve, x3, y3)
    }

    /// `(x, x + y)`. Constant time apart from whether this is infinity.
    fn negate(&self) -> Self {
        let Some((x, y)) = &self.coords else {
            return self.clone();
        };
        Self::new(self.curve, x.clone(), y.add(x))
    }

    fn normalize(&self) -> Self {
        self.clone()
    }

    fn projective_z(&self) -> Option<F2mFieldElement> {
        None
    }

    fn normalize_with_inverse(&self, _inverse: &F2mFieldElement) -> Self {
        self.clone()
    }
}

/// The same point on the same curve. Constant time in the coordinates.
impl PartialEq for F2mCtPoint<'_> {
    fn eq(&self, other: &Self) -> bool {
        (core::ptr::eq(self.curve, other.curve) || self.curve == other.curve)
            && self.coords == other.coords
    }
}

impl Eq for F2mCtPoint<'_> {}

/// Prints only whether the point is at infinity, never the coordinates.
impl fmt::Debug for F2mCtPoint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("F2mCtPoint")
            .field("infinity", &self.is_infinity())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use crate::{F2mCtCurve, F2mField, F2mVarCurve};
    use alloc::vec::Vec;
    use tc_bigint::{ArrayEncoding, PaddedBigUint};
    use tc_ec_core_v2::{Curve, FieldElement, Point};

    fn bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn integer(text: &str) -> PaddedBigUint {
        <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes(text)).unwrap()
    }

    const ONE: &str = "000000000000000000000000000000000000000001";

    // SEC 2 sect163k1 and sect163r2: (b, n, Gx, Gy), both with a = 1 and h = 2.
    const CURVES: [[&str; 4]; 2] = [
        [
            ONE,
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

    fn field() -> F2mField {
        F2mField::pentanomial(163, 3, 6, 7).unwrap()
    }

    #[test]
    fn the_ladder_agrees_with_the_variable_time_curve_including_the_edges() {
        for [b, n, gx, gy] in CURVES {
            let order = integer(n);
            let ct = F2mCtCurve::new(field(), &bytes(ONE), &bytes(b), Some(order.clone()), None)
                .unwrap();
            let var = F2mVarCurve::new(field(), &bytes(ONE), &bytes(b), Some(order.clone()), None)
                .unwrap();
            let g = ct.create_point(&bytes(gx), &bytes(gy)).unwrap();
            let h = var.create_point(&bytes(gx), &bytes(gy)).unwrap();

            let minus_one = integer("040000000000000000000292FE77E70C12A4234C32");
            let mut scalars: Vec<PaddedBigUint> = [0u64, 1, 2, 3, 4, 255, 65_537]
                .map(PaddedBigUint::from)
                .to_vec();
            scalars.extend([
                integer("0123456789ABCDEF0123456789ABCDEF01234567"),
                integer("03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
                order.clone(),
            ]);
            if b != ONE {
                scalars.push(minus_one);
            }
            for k in &scalars {
                let expected = <&F2mVarCurve as Curve>::multiply(&h, k);
                let actual = g.multiply(k);
                let expected = expected.x().zip(expected.y());
                assert!(actual.coords == expected, "b = {b}, k = {k:?}");
            }
            assert!(g.multiply(&order).coords.is_none());
        }
    }

    #[test]
    fn k_of_n_minus_one_gives_minus_g_where_the_recovery_divides_by_zero() {
        let [b, n, gx, gy] = CURVES[1];
        let ct = F2mCtCurve::new(field(), &bytes(ONE), &bytes(b), Some(integer(n)), None).unwrap();
        let g = ct.create_point(&bytes(gx), &bytes(gy)).unwrap();
        let minus_g = g.multiply(&integer("040000000000000000000292FE77E70C12A4234C32"));
        let (x, y) = g.coords.clone().unwrap();
        assert!(minus_g.coords == Some((x.clone(), x.add(&y))));
    }
}
