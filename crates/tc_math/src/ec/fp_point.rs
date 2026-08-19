//! Points on a prime-field elliptic curve.
//!
//! Corresponds to `FpPoint` in Bouncy Castle C#. A point holds an
//! `Arc<FpCurve>` back-reference to the curve it belongs to (the curve provides
//! the coefficient `a` needed by point arithmetic) plus its coordinates. The
//! representation mirrors bc's `m_x`, `m_y`, `m_zs`: `coords` holds `(X, Y)`
//! (`None` for the point at infinity), and `zs` holds the projective `Z`
//! coordinates — empty for affine, `[Z, ...]` for projective systems.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Add, Mul, Neg, Sub};

use crate::big_integer::BigInteger;
use crate::ec::CoordinateSystem;
use crate::ec::fp_curve::FpCurve;
use crate::ec::fp_field_element::FpFieldElement;

/// A point on an [`FpCurve`].
///
/// `coords` is `None` for the point at infinity (the group identity), otherwise
/// `Some((x, y))`. `zs` carries the projective `Z` coordinates and is empty in
/// affine coordinates.
#[derive(Clone)]
pub struct FpPoint {
    // 回指所屬曲線（提供 a、b、體域）。
    curve: Arc<FpCurve>,
    // 座標（bc m_x, m_y）；None = 無窮遠點。affine 時即 (x, y)，投影時為 (X, Y)。
    coords: Option<(FpFieldElement, FpFieldElement)>,
    // 投影 Z 座標（bc m_zs）；affine 為空 []，投影為 [Z, …]。
    zs: Vec<FpFieldElement>,
}

impl FpPoint {
    /// Creates the affine point `(x, y)` on `curve`.
    ///
    /// Does not verify that the point lies on the curve; that check will be a
    /// separate operation (bc `ValidatePoint`).
    pub fn new(curve: Arc<FpCurve>, x: FpFieldElement, y: FpFieldElement) -> Self {
        FpPoint {
            curve,
            coords: Some((x, y)),
            zs: Vec::new(), // affine：無 Z 座標
        }
    }

    /// Returns the point at infinity (the group identity) on `curve`.
    pub fn infinity(curve: Arc<FpCurve>) -> Self {
        FpPoint {
            curve,
            coords: None,
            zs: Vec::new(),
        }
    }

    /// Returns `true` if this is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.coords.is_none()
    }

    /// Encodes this point in SEC (X9.62 / SEC 1) format.
    ///
    /// `compressed` selects the `0x02`/`0x03` form (X plus a y-parity bit) over
    /// the uncompressed `0x04` form (X then Y). The point at infinity encodes as
    /// a single `0x00` byte. Corresponds to `GetEncoded` in Bouncy Castle.
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let (x, y) = match &self.coords {
            None => return alloc::vec![0x00], // 無窮遠點
            Some(coords) => coords,
        };
        let len = self.curve.field_element_encoding_length();
        let x_bytes = fixed_be(x.as_ref(), len);
        if compressed {
            let prefix = if y.as_ref().test_bit(0) { 0x03 } else { 0x02 };
            let mut out = Vec::with_capacity(1 + len);
            out.push(prefix);
            out.extend_from_slice(&x_bytes);
            out
        } else {
            let mut out = Vec::with_capacity(1 + 2 * len);
            out.push(0x04);
            out.extend_from_slice(&x_bytes);
            out.extend_from_slice(&fixed_be(y.as_ref(), len));
            out
        }
    }

    /// Returns the curve this point belongs to.
    pub fn curve(&self) -> &Arc<FpCurve> {
        &self.curve
    }

    /// Returns the affine x-coordinate, or `None` at infinity.
    pub fn x(&self) -> Option<&FpFieldElement> {
        self.coords.as_ref().map(|(x, _)| x)
    }

    /// Returns the affine y-coordinate, or `None` at infinity.
    pub fn y(&self) -> Option<&FpFieldElement> {
        self.coords.as_ref().map(|(_, y)| y)
    }

    /// Returns `2 * self` (point doubling).
    ///
    /// Corresponds to `Twice` in Bouncy Castle. Common guards live here; the
    /// per-coordinate-system formula is delegated to a helper. Only affine
    /// coordinates are implemented for now.
    pub fn twice(&self) -> Self {
        let (x1, y1) = match &self.coords {
            None => return self.clone(), // 2·O = O
            Some(coords) => coords,
        };
        if y1.is_zero() {
            // 切線垂直（y=0，此時 P = −P）→ 2P = O
            return FpPoint::infinity(Arc::clone(&self.curve));
        }
        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => self.twice_affine(x1, y1),
            _ => todo!("twice: only affine coordinates are implemented"),
        }
    }

    /// Affine point doubling via the tangent-slope formula
    /// `λ = (3x² + a) / 2y`, `x₃ = λ² − 2x`, `y₃ = λ(x − x₃) − y`.
    ///
    /// Assumes `self` is not the point at infinity and `y1 != 0` (checked by
    /// [`Self::twice`]). The division performs one field inversion.
    fn twice_affine(&self, x1: &FpFieldElement, y1: &FpFieldElement) -> Self {
        let a = self.curve.a();
        let x1_sq = x1.square();
        let three_x1_sq = &(&x1_sq + &x1_sq) + &x1_sq; // 3·x1²
        let lambda = &(&three_x1_sq + a) / &(y1 + y1); // (3x²+a)/(2y)
        let x3 = &lambda.square() - &(x1 + x1); // λ² − 2x
        let y3 = &(&lambda * &(x1 - &x3)) - y1; // λ(x − x3) − y
        FpPoint::new(Arc::clone(&self.curve), x3, y3)
    }

    /// Affine point addition of two distinct, non-infinity points via the
    /// secant-slope formula `γ = (y₂ − y₁)/(x₂ − x₁)`, `x₃ = γ² − x₁ − x₂`,
    /// `y₃ = γ(x₁ − x₃) − y₁`.
    ///
    /// Handles the coincident cases: `P == Q` delegates to [`Self::twice`], and
    /// `P == -Q` returns the point at infinity. Callers ([`Add`]) must have
    /// already handled the infinity operands.
    fn add_affine(&self, b: &FpPoint) -> Self {
        let (x1, y1) = self.coords.as_ref().expect("add_affine: lhs not infinity");
        let (x2, y2) = b.coords.as_ref().expect("add_affine: rhs not infinity");
        let dx = x2 - x1;
        let dy = y2 - y1;
        if dx.is_zero() {
            if dy.is_zero() {
                return self.twice(); // P == Q → 2P
            }
            return FpPoint::infinity(Arc::clone(&self.curve)); // P == −Q → O
        }
        let gamma = &dy / &dx; // (y2−y1)/(x2−x1)，含一次反元素
        let x3 = &(&gamma.square() - x1) - x2; // γ² − x1 − x2
        let y3 = &(&gamma * &(x1 - &x3)) - y1; // γ(x1 − x3) − y1
        FpPoint::new(Arc::clone(&self.curve), x3, y3)
    }

    /// Scalar multiplication `k * self` by left-to-right double-and-add (the
    /// simple binary method). Negative `k` is handled as `|k| * (-self)`.
    ///
    /// Kept as a named method so it survives alongside future windowed methods;
    /// [`Mul`] delegates here.
    pub fn mul_double_and_add(&self, k: &BigInteger) -> Self {
        // k·O = O、0·P = O
        if self.is_infinity() || k.is_zero() {
            return FpPoint::infinity(Arc::clone(&self.curve));
        }

        // k < 0：k·P = |k|·(−P)
        let (k, base) = if k.sign() < 0 {
            (-k, -self)
        } else {
            (k.clone(), self.clone())
        };

        // double-and-add，由最高位掃到最低位
        let mut result = FpPoint::infinity(Arc::clone(&self.curve));
        let mut i = k.bit_length();
        while i > 0 {
            i -= 1;
            result = result.twice();
            if k.test_bit(i) {
                result = &result + &base;
            }
        }
        result
    }

    // TODO(ec-point)：其餘待實作（對應 bc FpPoint / ECPointBase）：
    //   Jacobian 等座標系的 add_*/twice_* 子函式、mul_wnaf、encode/decode_point。
}

/// Two points are equal iff they lie on the same curve and have the same
/// coordinates (both the point at infinity, or the same affine `(x, y)`).
//
// TODO(ec-projective)：直接比對儲存的座標，只對 affine 正確。加入投影座標系後，
// eq 必須先 normalize 兩點再比較，因為 (X,Y,Z) 與 (λ²X,λ³Y,λZ) 是同一點。
impl PartialEq for FpPoint {
    fn eq(&self, other: &Self) -> bool {
        (Arc::ptr_eq(&self.curve, &other.curve) || self.curve == other.curve)
            && self.coords == other.coords
    }
}

impl Eq for FpPoint {}

impl core::fmt::Debug for FpPoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.coords {
            None => write!(f, "FpPoint(infinity)"),
            Some((x, y)) => write!(f, "FpPoint({}, {})", x.as_ref(), y.as_ref()),
        }
    }
}

/// Encodes a field-element value as fixed-length `len` big-endian bytes
/// (left-padded with zeros), as required by the SEC point encoding.
fn fixed_be(v: &BigInteger, len: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; len];
    let n = v.byte_length_unsigned(); // 值的最小位元組數（≤ len）
    // 寫進 buffer 右段 → 左邊自然留零（免中間 Vec）。
    v.to_bytes_be_unsigned_into(&mut buf[len - n..]);
    buf
}

/// Point negation: the additive inverse (negate `Y`, keep `X` and `Z`).
///
/// Corresponds to `Negate` in Bouncy Castle. With the unified representation the
/// two bc branches (affine vs projective) collapse: `zs` is simply carried
/// through, since negating `Y` never affects `Z`.
impl Neg for &FpPoint {
    type Output = FpPoint;

    fn neg(self) -> FpPoint {
        match &self.coords {
            None => self.clone(), // −O = O
            Some((x, y)) => FpPoint {
                curve: Arc::clone(&self.curve),
                coords: Some((x.clone(), -y)), // (X, −Y)
                zs: self.zs.clone(),           // 照抄 Z（affine 空、投影 [Z]）
            },
        }
    }
}

/// Point addition (the group law).
///
/// Corresponds to `Add` in Bouncy Castle. Handles the infinity operands here
/// and delegates the per-coordinate-system formula to a helper. Only affine
/// coordinates are implemented for now.
impl Add for &FpPoint {
    type Output = FpPoint;

    fn add(self, rhs: &FpPoint) -> FpPoint {
        debug_assert!(
            self.curve.q() == rhs.curve.q(),
            "add: points on different curves"
        );
        if self.is_infinity() {
            return rhs.clone(); // O + Q = Q
        }
        if rhs.is_infinity() {
            return self.clone(); // P + O = P
        }
        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => self.add_affine(rhs),
            _ => todo!("add: only affine coordinates are implemented"),
        }
    }
}

/// Point subtraction: `self - rhs = self + (-rhs)`.
///
/// Corresponds to `Subtract` in Bouncy Castle (`Add(b.Negate())`).
impl Sub for &FpPoint {
    type Output = FpPoint;

    fn sub(self, rhs: &FpPoint) -> FpPoint {
        self + &(-rhs)
    }
}

/// Scalar multiplication `k * self`.
///
/// Corresponds to `Multiply` in Bouncy Castle. Currently delegates to
/// [`FpPoint::mul_double_and_add`]; a windowed method can be selected here once
/// added (see the TODO on that function).
impl Mul<&BigInteger> for &FpPoint {
    type Output = FpPoint;

    fn mul(self, k: &BigInteger) -> FpPoint {
        // TODO(wnaf)：現在直接走 double-and-add。bc 預設用視窗化 NAF
        // （ECMultiplier → WNafL2RMultiplier，把 k 編成 non-adjacent form + 預算奇數
        // 倍點表，加法次數約降到 1/(w+1)）。之後加 mul_wnaf 後在這裡依情況選用。
        self.mul_double_and_add(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::big_integer::BigInteger;

    fn secp256k1() -> Arc<FpCurve> {
        let p = BigInteger::from_str_radix(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap();
        Arc::new(FpCurve::new(
            p,
            BigInteger::from_u32(0),
            BigInteger::from_u32(7),
            None,
            None,
        ))
    }

    #[test]
    fn infinity_has_no_coords() {
        let inf = FpPoint::infinity(secp256k1());
        assert!(inf.is_infinity());
        assert!(inf.x().is_none());
        assert!(inf.y().is_none());
    }

    #[test]
    fn affine_point_exposes_coords() {
        let curve = secp256k1();
        let x = curve.field_element(BigInteger::from_u32(2));
        let y = curve.field_element(BigInteger::from_u32(3));
        let p = FpPoint::new(Arc::clone(&curve), x, y);
        assert!(!p.is_infinity());
        assert_eq!(p.x().unwrap().as_ref(), &BigInteger::from_u32(2));
        assert_eq!(p.y().unwrap().as_ref(), &BigInteger::from_u32(3));
    }

    // 教科書曲線 y² = x³ + 2x + 2 over GF(17)。
    fn curve17() -> Arc<FpCurve> {
        Arc::new(FpCurve::new(
            BigInteger::from_u32(17),
            BigInteger::from_u32(2),
            BigInteger::from_u32(2),
            None,
            None,
        ))
    }

    fn point17(curve: &Arc<FpCurve>, x: u32, y: u32) -> FpPoint {
        FpPoint::new(
            Arc::clone(curve),
            curve.field_element(BigInteger::from_u32(x)),
            curve.field_element(BigInteger::from_u32(y)),
        )
    }

    #[test]
    fn twice_matches_known_double() {
        let curve = curve17();
        // 2·(5,1) = (6,3)。
        let g = point17(&curve, 5, 1);
        let two_g = g.twice();
        assert_eq!(two_g.x().unwrap().as_ref(), &BigInteger::from_u32(6));
        assert_eq!(two_g.y().unwrap().as_ref(), &BigInteger::from_u32(3));
    }

    #[test]
    fn twice_infinity_and_y_zero() {
        let curve = curve17();
        // 2·O = O。
        assert!(FpPoint::infinity(Arc::clone(&curve)).twice().is_infinity());
        // y = 0（P = −P）→ 2P = O。
        assert!(point17(&curve, 5, 0).twice().is_infinity());
    }

    #[test]
    fn add_distinct_points() {
        let curve = curve17();
        // G + 2G = 3G = (10, 6)。
        let sum = &point17(&curve, 5, 1) + &point17(&curve, 6, 3);
        assert_eq!(sum.x().unwrap().as_ref(), &BigInteger::from_u32(10));
        assert_eq!(sum.y().unwrap().as_ref(), &BigInteger::from_u32(6));
    }

    #[test]
    fn add_same_point_doubles() {
        let curve = curve17();
        // G + G = 2G = (6, 3)。
        let g = point17(&curve, 5, 1);
        let sum = &g + &g;
        assert_eq!(sum.x().unwrap().as_ref(), &BigInteger::from_u32(6));
        assert_eq!(sum.y().unwrap().as_ref(), &BigInteger::from_u32(3));
    }

    #[test]
    fn subtract_is_add_of_negation() {
        let curve = curve17();
        let g = point17(&curve, 5, 1);
        // 3G − G = 2G = (6, 3)。
        let r = &point17(&curve, 10, 6) - &g;
        assert_eq!(r.x().unwrap().as_ref(), &BigInteger::from_u32(6));
        assert_eq!(r.y().unwrap().as_ref(), &BigInteger::from_u32(3));
        // G − G = O。
        assert!((&g - &g).is_infinity());
    }

    #[test]
    fn add_inverse_and_identity() {
        let curve = curve17();
        let g = point17(&curve, 5, 1);
        // P + (−P) = O。
        assert!((&g + &(-&g)).is_infinity());
        // P + O = P、O + P = P。
        let inf = FpPoint::infinity(Arc::clone(&curve));
        assert_eq!((&g + &inf).x().unwrap().as_ref(), &BigInteger::from_u32(5));
        assert_eq!((&inf + &g).x().unwrap().as_ref(), &BigInteger::from_u32(5));
    }

    #[test]
    fn multiply_matches_known_multiples() {
        // 曲線 y²=x³+2x+2 / GF(17)，G=(5,1)，階 19。已知倍數:
        // 2G=(6,3), 4G=(3,1), 18G=(5,16)。
        let curve = curve17();
        let g = point17(&curve, 5, 1);
        let two_g = &g * &BigInteger::from_u32(2);
        assert_eq!(two_g.x().unwrap().as_ref(), &BigInteger::from_u32(6));
        assert_eq!(two_g.y().unwrap().as_ref(), &BigInteger::from_u32(3));
        let four_g = &g * &BigInteger::from_u32(4);
        assert_eq!(four_g.x().unwrap().as_ref(), &BigInteger::from_u32(3));
        assert_eq!(four_g.y().unwrap().as_ref(), &BigInteger::from_u32(1));
    }

    #[test]
    fn multiply_edge_cases() {
        let curve = curve17();
        let g = point17(&curve, 5, 1);
        // 0·G = O、19·G = O（曲線階為 19）。
        assert!((&g * &BigInteger::from_u32(0)).is_infinity());
        assert!((&g * &BigInteger::from_u32(19)).is_infinity());
        // k·O = O。
        assert!((&FpPoint::infinity(Arc::clone(&curve)) * &BigInteger::from_u32(5)).is_infinity());
        // (−1)·G = −G = (5,16)。
        let neg = &g * &BigInteger::from_i32(-1);
        assert_eq!(neg.x().unwrap().as_ref(), &BigInteger::from_u32(5));
        assert_eq!(neg.y().unwrap().as_ref(), &BigInteger::from_u32(16));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let curve = curve17();
        let g = point17(&curve, 5, 1);

        // 未壓縮:0x04 + X + Y。
        let enc = g.encode(false);
        assert_eq!(enc, vec![0x04, 5, 1]);
        let dec = curve.decode_point(&enc).unwrap();
        assert_eq!(dec.x().unwrap().as_ref(), &BigInteger::from_u32(5));
        assert_eq!(dec.y().unwrap().as_ref(), &BigInteger::from_u32(1));

        // 壓縮:y=1 奇 → 0x03 + X。
        let encc = g.encode(true);
        assert_eq!(encc, vec![0x03, 5]);
        assert_eq!(
            curve.decode_point(&encc).unwrap().y().unwrap().as_ref(),
            &BigInteger::from_u32(1)
        );

        // 無窮遠點 → 單一 0x00。
        assert_eq!(FpPoint::infinity(Arc::clone(&curve)).encode(true), vec![0x00]);
    }

    #[test]
    fn eq_and_debug() {
        let curve = curve17();
        let g = point17(&curve, 5, 1);
        // 同曲線同座標 → 相等；不同座標 / 無窮遠點 → 不等。
        assert_eq!(g, point17(&curve, 5, 1));
        assert_ne!(g, point17(&curve, 6, 3));
        let inf = FpPoint::infinity(Arc::clone(&curve));
        assert_eq!(inf, FpPoint::infinity(Arc::clone(&curve)));
        assert_ne!(g, inf);
        // Debug。
        assert_eq!(alloc::format!("{g:?}"), "FpPoint(5, 1)");
        assert_eq!(alloc::format!("{inf:?}"), "FpPoint(infinity)");
    }

    #[test]
    fn negate_flips_y() {
        let curve = secp256k1();
        let x = curve.field_element(BigInteger::from_u32(2));
        let y = curve.field_element(BigInteger::from_u32(3));
        let p = FpPoint::new(Arc::clone(&curve), x, y);
        let neg = -&p;
        // x 不變，y → q − 3。
        assert_eq!(neg.x().unwrap().as_ref(), &BigInteger::from_u32(2));
        assert_eq!(
            neg.y().unwrap().as_ref(),
            &(curve.q() - &BigInteger::from_u32(3))
        );
        // −O = O。
        assert!((-&FpPoint::infinity(curve)).is_infinity());
    }
}
