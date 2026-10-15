use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use tc_bigint::{PaddedBigUint, Word};
use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
use tc_ec_core_v2::{FieldElement, Point, PointEncodeError};

use crate::{FpCtCurve, FpFieldElement, sec1};

const WINDOW: u32 = 4;

/// A point on an [`FpCtCurve`] in homogeneous coordinates `(X : Y : Z)`, with infinity
/// as `(0 : 1 : 0)`.
///
/// Every operation takes the same field operations whatever the coordinates and the
/// scalar, so a point and a scalar may be secret. Where a method returns a `bool` or an
/// `Option`, that answer alone is revealed.
#[derive(Clone)]
pub struct FpCtPoint<'a> {
    curve: &'a FpCtCurve<'a>,
    x: FpFieldElement<'a>,
    y: FpFieldElement<'a>,
    z: FpFieldElement<'a>,
}

impl<'a> FpCtPoint<'a> {
    pub(crate) fn new(
        curve: &'a FpCtCurve<'a>,
        x: FpFieldElement<'a>,
        y: FpFieldElement<'a>,
    ) -> Self {
        Self {
            curve,
            x,
            y,
            z: curve.field().one(),
        }
    }

    pub(crate) fn infinity(curve: &'a FpCtCurve<'a>) -> Self {
        let field = curve.field();
        Self {
            curve,
            x: field.zero(),
            y: field.one(),
            z: field.zero(),
        }
    }

    /// The affine `(x, y)`, or `None` at infinity, at the cost of one inversion. Constant
    /// time apart from whether this is infinity.
    pub fn affine(&self) -> Option<(FpFieldElement<'a>, FpFieldElement<'a>)> {
        let inverse = self.z.invert()?;
        Some((self.x.multiply(&inverse), self.y.multiply(&inverse)))
    }

    /// Whether `Y²Z = X³ + aXZ² + bZ³`; infinity counts as on the curve. The subgroup is
    /// not checked; see [`is_valid`](Self::is_valid). Constant time; only the answer is
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
        let mut table = Vec::with_capacity(1 << WINDOW);
        table.push(Self::infinity(self.curve));
        for i in 1..1 << WINDOW {
            let next = table[i - 1].add(self);
            table.push(next);
        }

        let width = scalar.as_limbs().len() as u32 * Word::BITS;
        let mut result = Self::infinity(self.curve);
        for window in (0..width / WINDOW).rev() {
            for _ in 0..WINDOW {
                result = result.twice();
            }
            let mut index = 0u8;
            for bit in (0..WINDOW).rev() {
                index = (index << 1) | u8::from(scalar.bit(window * WINDOW + bit));
            }
            result = result.add(&lookup(&table, index));
        }
        result
    }

    fn with(&self, x: FpFieldElement<'a>, y: FpFieldElement<'a>, z: FpFieldElement<'a>) -> Self {
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
        sec1::encode(
            self.curve.field(),
            self.affine().as_ref(),
            compressed,
            output,
        )
    }

    /// The SEC 1 encoding. Constant time apart from whether this is infinity.
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let mut output = vec![0; self.encoded_length(compressed)];
        self.encode_to(compressed, &mut output)
            .expect("the buffer has the exact length");
        output
    }
}

fn lookup<'a>(table: &[FpCtPoint<'a>], index: u8) -> FpCtPoint<'a> {
    let mut selected = table[0].clone();
    for (i, entry) in (0u8..).zip(table).skip(1) {
        selected = FpCtPoint::conditional_select(&selected, entry, i.ct_eq(&index));
    }
    selected
}

/// `twice_plus`, `three_times` and `times_pow2` take the default loops over public
/// counts. Constant time, apart from the `bool` and `Option` answers.
impl<'a> Point for FpCtPoint<'a> {
    type Curve = &'a FpCtCurve<'a>;

    fn curve(&self) -> &'a FpCtCurve<'a> {
        self.curve
    }

    /// On the curve and, when the cofactor is not one and the order is known, `nP = O`.
    /// Constant time; only the answer is revealed.
    fn is_valid(&self) -> bool {
        let one = PaddedBigUint::from(1u8);
        self.is_on_curve()
            && (self.curve.cofactor().is_some_and(|h| *h == one)
                || self
                    .curve
                    .order()
                    .is_none_or(|n| self.multiply(n).is_infinity()))
    }

    fn infinity(&self) -> Self {
        Self::infinity(self.curve)
    }

    /// Whether this is infinity. Constant time; only the answer is revealed.
    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// The affine x. Constant time apart from whether this is infinity.
    fn x(&self) -> Option<FpFieldElement<'a>> {
        self.affine().map(|(x, _)| x)
    }

    /// The affine y. Constant time apart from whether this is infinity.
    fn y(&self) -> Option<FpFieldElement<'a>> {
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
        let t1 = t0.double().add(&t0).add(&a.multiply(&t2));
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
        let t3 = x.multiply(y).double();
        let z3 = x.multiply(z).double();
        let x3 = a.multiply(&z3);
        let y3 = x3.add(&b3.multiply(&t2));
        let x3 = t1.subtract(&y3);
        let y3 = t1.add(&y3);
        let y3 = x3.multiply(&y3);
        let x3 = t3.multiply(&x3);
        let z3 = b3.multiply(&z3);
        let t2 = a.multiply(&t2);
        let t3 = a.multiply(&t0.subtract(&t2)).add(&z3);
        let t0 = t0.double().add(&t0).add(&t2);
        let y3 = y3.add(&t0.multiply(&t3));
        let t2 = y.multiply(z).double();
        let x3 = x3.subtract(&t2.multiply(&t3));
        let z3 = t2.multiply(&t1).double().double();
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

    fn projective_z(&self) -> Option<FpFieldElement<'a>> {
        (!self.is_infinity()).then(|| self.z.clone())
    }

    fn normalize_with_inverse(&self, inverse: &FpFieldElement<'a>) -> Self {
        self.with(
            self.x.multiply(inverse),
            self.y.multiply(inverse),
            self.z.multiply(inverse),
        )
    }
}

/// `a` or `b`, as the choice says. Constant time. Panics when the curves differ.
impl ConditionallySelectable for FpCtPoint<'_> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        a.assert_same_curve(b);
        a.with(
            FpFieldElement::conditional_select(&a.x, &b.x, choice),
            FpFieldElement::conditional_select(&a.y, &b.y, choice),
            FpFieldElement::conditional_select(&a.z, &b.z, choice),
        )
    }
}

/// The same point whatever the projective scale: `X₁Z₂ = X₂Z₁` and `Y₁Z₂ = Y₂Z₁`.
/// Constant time. Panics when the curves differ.
impl ConstantTimeEq for FpCtPoint<'_> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.assert_same_curve(rhs);
        self.x.multiply(&rhs.z).ct_eq(&rhs.x.multiply(&self.z))
            & self.y.multiply(&rhs.z).ct_eq(&rhs.y.multiply(&self.z))
    }
}

/// Through `ct_eq`; points on different curves are not equal. Constant time; only the
/// answer is revealed.
impl PartialEq for FpCtPoint<'_> {
    fn eq(&self, other: &Self) -> bool {
        (core::ptr::eq(self.curve, other.curve) || self.curve == other.curve)
            && self.ct_eq(other).unwrap_u8() == 1
    }
}

impl Eq for FpCtPoint<'_> {}

/// Prints nothing of the point, which may be secret.
impl fmt::Debug for FpCtPoint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FpCtPoint").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use tc_bigint::PaddedBigUint;
    use tc_constant_time::{Choice, ConditionallySelectable};
    use tc_ec_core_v2::{Point, PrimeFieldElement};

    use crate::{FpCtCurve, FpCtPoint, FpField, FpVarCurve, FpVarPoint};

    fn int(value: u8) -> PaddedBigUint {
        PaddedBigUint::from(value)
    }

    fn hex(text: &str) -> PaddedBigUint {
        let bytes: alloc::vec::Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect();
        <PaddedBigUint as tc_bigint::ArrayEncoding<u8>>::from_be(&bytes).unwrap()
    }

    fn ct(point: &FpCtPoint<'_>) -> Option<(PaddedBigUint, PaddedBigUint)> {
        point
            .affine()
            .map(|(x, y)| (x.to_big_uint(), y.to_big_uint()))
    }

    fn var(point: &FpVarPoint<'_>) -> Option<(PaddedBigUint, PaddedBigUint)> {
        Some((point.x()?.to_big_uint(), point.y()?.to_big_uint()))
    }

    // y² = x³ + 2x + 2 over F17, of prime order 19, generated by (5, 1).
    #[test]
    fn every_multiple_matches_the_variable_time_curve() {
        let field = FpField::new(int(17)).unwrap();
        let ct_curve =
            FpCtCurve::new(&field, &int(2), &int(2), Some(int(19)), Some(int(1))).unwrap();
        let var_curve =
            FpVarCurve::new(&field, &int(2), &int(2), Some(int(19)), Some(int(1))).unwrap();
        let g = ct_curve.create_point(&int(5), &int(1)).unwrap();
        let h = var_curve.create_point(&int(5), &int(1)).unwrap();
        for k in 0..40 {
            let p = g.multiply(&int(k));
            assert_eq!(ct(&p), var(&h.multiply(&int(k))), "k = {k}");
            assert!(p.is_on_curve() && p.is_valid(), "k = {k}");
            assert_eq!(p.add(&g), g.multiply(&int(k + 1)), "k = {k}");
            assert_eq!(p.twice(), g.multiply(&int(2 * k)), "k = {k}");
        }
    }

    #[test]
    fn the_complete_formulas_take_infinity_doubling_and_opposites() {
        let field = FpField::new(int(17)).unwrap();
        let curve = FpCtCurve::new(&field, &int(2), &int(2), Some(int(19)), Some(int(1))).unwrap();
        let g = curve.create_point(&int(5), &int(1)).unwrap();
        let o = curve.infinity();
        assert_eq!(g.add(&g), g.twice());
        assert!(g.add(&g.negate()).is_infinity());
        assert!(g.subtract(&g).is_infinity());
        assert_eq!(o.add(&g), g);
        assert_eq!(g.add(&o), g);
        assert!(o.add(&o).is_infinity() && o.twice().is_infinity());
        assert!(o.is_on_curve() && o.affine().is_none());
        assert_ne!(g, o);
    }

    #[test]
    fn conditional_select_and_equality_follow_the_choice() {
        let field = FpField::new(int(17)).unwrap();
        let curve = FpCtCurve::new(&field, &int(2), &int(2), None, None).unwrap();
        let g = curve.create_point(&int(5), &int(1)).unwrap();
        let two_g = g.twice();
        assert_eq!(
            FpCtPoint::conditional_select(&g, &two_g, Choice::from_lsb(0)),
            g
        );
        assert_eq!(
            FpCtPoint::conditional_select(&g, &two_g, Choice::from_lsb(1)),
            two_g
        );
        assert_eq!(g.add(&two_g).subtract(&two_g), g);
    }

    #[test]
    fn p256_matches_the_nist_vector_and_the_variable_time_curve() {
        let p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        let a = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
        let b = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
        let gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        let gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        let n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
        let x2 = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
        let y2 = "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
        let k = "c51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd";

        let field = FpField::new(hex(p)).unwrap();
        let curve = FpCtCurve::new(&field, &hex(a), &hex(b), Some(hex(n)), Some(int(1))).unwrap();
        let var_curve =
            FpVarCurve::new(&field, &hex(a), &hex(b), Some(hex(n)), Some(int(1))).unwrap();
        let g = curve.create_point(&hex(gx), &hex(gy)).unwrap();
        let h = var_curve.create_point(&hex(gx), &hex(gy)).unwrap();

        assert!(g.is_on_curve());
        assert_eq!(ct(&g.twice()), Some((hex(x2), hex(y2))));
        assert!(g.multiply(&hex(n)).is_infinity());
        assert_eq!(ct(&g.multiply(&hex(k))), var(&h.multiply(&hex(k))));

        let encoded = g.multiply(&hex(k)).encode(true);
        assert_eq!(encoded.len(), 33);
        assert_eq!(curve.decode_point(&encoded), Ok(g.multiply(&hex(k))));
        assert_eq!(encoded, h.multiply(&hex(k)).encode(true));
    }
}
