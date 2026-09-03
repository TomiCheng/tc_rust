//! Points on binary-field (F2m) short-Weierstrass curves.
//!
//! Corresponds to `F2mPoint` in Bouncy Castle C#. The curve equation over `GF(2ᵐ)`
//! is `y² + xy = x³ + ax² + b` (unlike the Fp form `y² = x³ + ax + b`), so the point
//! arithmetic formulas differ — but the data layout mirrors [`FpPoint`](super::FpPoint)
//! exactly (bc shares the same `ECPointBase` `m_curve`/`m_x`/`m_y`/`m_zs`).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Add, Mul, Neg, Sub};

use crate::big_integer::BigInteger;
use crate::ec::coordinate_system::CoordinateSystem;
use crate::ec::f2m_curve::F2mCurve;
use crate::ec::f2m_field_element::F2mFieldElement;

/// A point on an [`F2mCurve`].
///
/// `coords` is `None` for the point at infinity (the group identity), otherwise
/// `Some((x, y))`. `zs` carries the projective `Z` coordinates and is empty in
/// affine coordinates. Construction and arithmetic are added later; this is the data
/// layout only.
#[derive(Clone)]
pub struct F2mPoint {
    // 回指所屬曲線（提供 a、b、體域）。
    curve: Arc<F2mCurve>,
    // 座標（bc m_x, m_y）；None = 無窮遠點。affine 時即 (x, y)，投影時為 (X, Y)。
    coords: Option<(F2mFieldElement, F2mFieldElement)>,
    // 投影 Z 座標（bc m_zs）；affine 為空 []，投影為 [Z, …]。
    zs: Vec<F2mFieldElement>,
}

impl F2mPoint {
    /// Creates the affine point `(x, y)` on `curve`.
    ///
    /// Does not verify that the point lies on the curve; that check is a separate
    /// operation (bc `ValidatePoint`).
    pub fn new(curve: Arc<F2mCurve>, x: F2mFieldElement, y: F2mFieldElement) -> Self {
        F2mPoint {
            curve,
            coords: Some((x, y)),
            zs: Vec::new(),
        }
    }

    /// Returns the point at infinity (the group identity) on `curve`.
    pub fn infinity(curve: Arc<F2mCurve>) -> Self {
        F2mPoint {
            curve,
            coords: None,
            zs: Vec::new(),
        }
    }

    /// Returns `true` if this is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.coords.is_none()
    }

    /// Returns the affine `x` coordinate, or `None` at infinity.
    pub fn x(&self) -> Option<&F2mFieldElement> {
        self.coords.as_ref().map(|(x, _)| x)
    }

    /// Returns the affine `y` coordinate, or `None` at infinity.
    pub fn y(&self) -> Option<&F2mFieldElement> {
        self.coords.as_ref().map(|(_, y)| y)
    }

    /// Returns the curve this point belongs to.
    pub fn curve(&self) -> &Arc<F2mCurve> {
        &self.curve
    }

    /// Encodes this point in SEC (X9.62 / SEC 1) format.
    ///
    /// `compressed` selects the `0x02`/`0x03` form (X plus a parity bit) over the
    /// uncompressed `0x04` form (X then Y). The point at infinity encodes as a single
    /// `0x00` byte. Corresponds to `GetEncoded` in bc.
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let (x, y) = match &self.coords {
            None => return alloc::vec![0x00], // 無窮遠點
            Some(coords) => coords,
        };
        let len = self.curve.field_element_encoding_length();
        let x_bytes = fixed_be(&x.to_big_integer(), len);
        if compressed {
            let prefix = if Self::compression_y_tilde(x, y) {
                0x03
            } else {
                0x02
            };
            let mut out = Vec::with_capacity(1 + len);
            out.push(prefix);
            out.extend_from_slice(&x_bytes);
            out
        } else {
            let mut out = Vec::with_capacity(1 + 2 * len);
            out.push(0x04);
            out.extend_from_slice(&x_bytes);
            out.extend_from_slice(&fixed_be(&y.to_big_integer(), len));
            out
        }
    }

    /// The SEC compression parity bit for the affine point `(x, y)`. Corresponds to bc
    /// `CompressionYTilde` (affine branch): `false` when `x = 0`, otherwise the low bit
    /// of `z = y / x`.
    fn compression_y_tilde(x: &F2mFieldElement, y: &F2mFieldElement) -> bool {
        if x.is_zero() {
            false
        } else {
            (y / x).test_bit_zero() // z = y/x
        }
    }

    /// Returns `2 * self` (point doubling).
    ///
    /// Corresponds to `Twice` in bc. Guards live here; the per-coordinate-system
    /// formula is delegated. Only affine coordinates are implemented for now.
    pub fn twice(&self) -> Self {
        let (x1, y1) = match &self.coords {
            None => return self.clone(), // 2·O = O
            Some(coords) => coords,
        };
        if x1.is_zero() {
            // X = 0 的點是自身的加法反元素 → 2P = O
            return F2mPoint::infinity(Arc::clone(&self.curve));
        }
        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => self.twice_affine(x1, y1),
            _ => todo!("twice: only affine coordinates are implemented"),
        }
    }

    /// Affine doubling on `y² + xy = x³ + ax² + b`: `λ = y/x + x`,
    /// `x₃ = λ² + λ + a`, `y₃ = x₁² + x₃·(λ + 1)`.
    ///
    /// Assumes not infinity and `x1 != 0` (checked by [`Self::twice`]); the division
    /// performs one field inversion.
    fn twice_affine(&self, x1: &F2mFieldElement, y1: &F2mFieldElement) -> Self {
        let a = self.curve.a();
        let lambda = &(y1 / x1) + x1; // λ = y/x + x
        let x3 = &(&lambda.square() + &lambda) + a; // λ² + λ + a
        let y3 = x1.square_plus_product(&x3, &lambda.add_one()); // x₁² + x₃·(λ+1)
        F2mPoint::new(Arc::clone(&self.curve), x3, y3)
    }

    /// Affine addition on `y² + xy = x³ + ax² + b`. With `dx = x₁+x₂`, `dy = y₁+y₂`:
    /// `λ = dy/dx`, `x₃ = λ² + λ + dx + a`, `y₃ = λ·(x₁+x₃) + x₃ + y₁`. Coincident
    /// cases: `dx = 0` means `x₁ = x₂` → either `P == Q` (`dy = 0`, delegate to
    /// [`twice`](Self::twice)) or `P == −Q` (return infinity).
    fn add_affine(
        &self,
        x1: &F2mFieldElement,
        y1: &F2mFieldElement,
        x2: &F2mFieldElement,
        y2: &F2mFieldElement,
    ) -> Self {
        let dx = x1 + x2; // x₁ + x₂（char 2：XOR）
        let dy = y1 + y2; // y₁ + y₂
        if dx.is_zero() {
            if dy.is_zero() {
                return self.twice(); // P == Q
            }
            return F2mPoint::infinity(Arc::clone(&self.curve)); // P == −Q
        }
        let a = self.curve.a();
        let lambda = &dy / &dx; // λ = dy/dx
        let x3 = &(&(&lambda.square() + &lambda) + &dx) + a; // λ² + λ + dx + a
        let y3 = &(&(&lambda * &(x1 + &x3)) + &x3) + y1; // λ(x₁+x₃) + x₃ + y₁
        F2mPoint::new(Arc::clone(&self.curve), x3, y3)
    }

    /// Scalar multiplication `k * self` by left-to-right double-and-add (the simple
    /// binary method). Negative `k` is handled as `|k| * (−self)`.
    ///
    /// Kept as a named method so it survives alongside future windowed methods;
    /// [`Mul`] delegates here.
    pub fn mul_double_and_add(&self, k: &BigInteger) -> Self {
        // k·O = O、0·P = O
        if self.is_infinity() || k.is_zero() {
            return F2mPoint::infinity(Arc::clone(&self.curve));
        }

        // k < 0：k·P = |k|·(−P)
        let (k, base) = if k.sign() < 0 {
            (-k, -self)
        } else {
            (k.clone(), self.clone())
        };

        // double-and-add，由最高位掃到最低位
        let mut result = F2mPoint::infinity(Arc::clone(&self.curve));
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

    // TODO(ec-f2m-point)：其餘待實作 —— Koblitz τ-adic（WTauNaf）與一般 WNAF 純量乘、
    // lambda/homogeneous 座標系的 add_*/twice_*、點 encode/decode。
}

/// Scalar multiplication `k * self`.
///
/// Corresponds to the `ECMultiplier` path in bc. For now this is plain
/// double-and-add; windowed / τ-adic methods are a later optimization.
impl Mul<&BigInteger> for &F2mPoint {
    type Output = F2mPoint;

    fn mul(self, k: &BigInteger) -> F2mPoint {
        // TODO(ec-f2m-point): bc 對 Koblitz 曲線預設走 WTauNafMultiplier，其餘走 WNAF。
        self.mul_double_and_add(k)
    }
}

/// Two points are equal iff they lie on the same curve and have the same coordinates
/// (both the point at infinity, or the same affine `(x, y)`).
//
// TODO(ec-projective)：直接比對儲存的座標，只對 affine 正確。加入投影座標系後，eq
// 必須先 normalize 兩點再比較（(X,Y,Z) 與 (λ²X,λ³Y,λZ) 是同一點）。
impl PartialEq for F2mPoint {
    fn eq(&self, other: &Self) -> bool {
        (Arc::ptr_eq(&self.curve, &other.curve) || self.curve == other.curve)
            && self.coords == other.coords
    }
}

impl Eq for F2mPoint {}

impl core::fmt::Debug for F2mPoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.coords {
            None => write!(f, "F2mPoint(infinity)"),
            Some((x, y)) => {
                write!(
                    f,
                    "F2mPoint({}, {})",
                    x.to_big_integer(),
                    y.to_big_integer()
                )
            }
        }
    }
}

/// Encodes a field-element value as fixed-length `len` big-endian bytes (left-padded
/// with zeros), as required by the SEC point encoding.
fn fixed_be(v: &BigInteger, len: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; len];
    let n = v.byte_length_unsigned(); // 值的最小位元組數（≤ len）
    v.to_bytes_be_unsigned_into(&mut buf[len - n..]); // 寫右段 → 左邊留零
    buf
}

/// Point addition (the group law). Corresponds to `Add` in bc. Infinity operands are
/// handled here; the per-coordinate-system formula is delegated. Only affine
/// coordinates are implemented for now.
impl Add for &F2mPoint {
    type Output = F2mPoint;

    fn add(self, rhs: &F2mPoint) -> F2mPoint {
        debug_assert!(
            Arc::ptr_eq(&self.curve, &rhs.curve) || self.curve == rhs.curve,
            "add: points on different curves"
        );
        let (x1, y1) = match &self.coords {
            None => return rhs.clone(), // O + Q = Q
            Some(c) => c,
        };
        let (x2, y2) = match &rhs.coords {
            None => return self.clone(), // P + O = P
            Some(c) => c,
        };
        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => self.add_affine(x1, y1, x2, y2),
            _ => todo!("add: only affine coordinates are implemented"),
        }
    }
}

/// Point subtraction `self − rhs`, i.e. `self + (−rhs)`.
///
/// Corresponds to `Subtract` in bc (`Add(b.Negate())`, with a fast path when `rhs`
/// is the point at infinity).
impl Sub for &F2mPoint {
    type Output = F2mPoint;

    fn sub(self, rhs: &F2mPoint) -> F2mPoint {
        if rhs.is_infinity() {
            return self.clone(); // P − O = P
        }
        self + &(-rhs) // P + (−Q)
    }
}

/// Point negation. In `GF(2ᵐ)` the additive inverse of the affine point `(x, y)` is
/// `(x, x + y)` — not Fp's `(x, −y)`, because the curve is `y² + xy = x³ + ax² + b`.
/// The point at infinity and the 2-torsion points (`x = 0`, where `−P = P`) are their
/// own inverse.
///
/// Corresponds to `Negate` in bc. Only affine coordinates are implemented; other
/// systems have their own formula (bc's `switch`), hence the coordinate-system match.
impl Neg for &F2mPoint {
    type Output = F2mPoint;

    fn neg(self) -> F2mPoint {
        let (x, y) = match &self.coords {
            None => return self.clone(), // −O = O
            Some(coords) => coords,
        };
        if x.is_zero() {
            return self.clone(); // x = 0：2-撓點，−P = P
        }
        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => {
                // −P = (x, y + x)（char 2：y XOR x；對齊 bc Y.Add(X)）
                F2mPoint::new(Arc::clone(&self.curve), x.clone(), y + x)
            }
            _ => todo!("neg: only affine coordinates are implemented"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::big_integer::BigInteger;

    // 取一條可建點的 F2m 曲線（GF(2^4)，x^4+x+1）。本組只驗負點的代數結構，
    // 不要求點真的在曲線上。
    fn curve16() -> Arc<F2mCurve> {
        Arc::new(F2mCurve::trinomial(
            4,
            1,
            BigInteger::from_u32(0),
            BigInteger::from_u32(1),
            None,
            None,
        ))
    }

    #[test]
    fn neg_infinity_is_infinity() {
        let c = curve16();
        assert!((-&c.infinity()).is_infinity());
    }

    #[test]
    fn neg_x_zero_is_self() {
        // x = 0 的 2-撓點：−P = P。
        let c = curve16();
        let p = c.create_point(BigInteger::from_u32(0), BigInteger::from_u32(0b0011));
        let np = -&p;
        assert_eq!(np.x().unwrap().to_big_integer(), BigInteger::from_u32(0));
        assert_eq!(
            np.y().unwrap().to_big_integer(),
            BigInteger::from_u32(0b0011)
        ); // y 不變
    }

    #[test]
    fn neg_general_point_and_involution() {
        let c = curve16();
        // P = (x, y)，x≠0 → −P = (x, y+x)。
        let p = c.create_point(BigInteger::from_u32(0b0010), BigInteger::from_u32(0b0111));
        let np = -&p;
        assert_eq!(
            np.x().unwrap().to_big_integer(),
            BigInteger::from_u32(0b0010)
        ); // x 不變
        // y + x = 0b0111 ^ 0b0010 = 0b0101
        assert_eq!(
            np.y().unwrap().to_big_integer(),
            BigInteger::from_u32(0b0101)
        );
        // 對合：−(−P) = P
        let nnp = -&np;
        assert_eq!(
            nnp.x().unwrap().to_big_integer(),
            p.x().unwrap().to_big_integer()
        );
        assert_eq!(
            nnp.y().unwrap().to_big_integer(),
            p.y().unwrap().to_big_integer()
        );
    }

    // SEC 2 sect163k1（Koblitz）：x^163+x^7+x^6+x^3+1，a=1，b=1。
    fn sect163k1() -> Arc<F2mCurve> {
        Arc::new(F2mCurve::pentanomial(
            163,
            3,
            6,
            7,
            BigInteger::from_u32(1),
            BigInteger::from_u32(1),
            None,
            None,
        ))
    }

    fn base_g(c: &Arc<F2mCurve>) -> F2mPoint {
        let gx =
            BigInteger::from_str_radix("02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8", 16).unwrap();
        let gy =
            BigInteger::from_str_radix("0289070FB05D38FF58321F2E800536D538CCDAA3D9", 16).unwrap();
        c.create_point(gx, gy)
    }

    // 驗點 (x, y) 是否滿足 y² + xy = x³ + ax² + b。
    fn on_curve(p: &F2mPoint) -> bool {
        let c = p.curve();
        let (x, y) = (p.x().unwrap(), p.y().unwrap());
        let lhs = &y.square() + &(x * y); // y² + xy
        let x2 = x.square();
        let rhs = &(&(&x2 * x) + &(c.a() * &x2)) + c.b(); // x³ + a·x² + b
        lhs == rhs
    }

    #[test]
    fn twice_sect163k1_base_point_stays_on_curve() {
        let c = sect163k1();
        let g = base_g(&c);
        assert!(on_curve(&g), "基點 G 應在曲線上");

        let two_g = g.twice();
        assert!(!two_g.is_infinity());
        assert!(on_curve(&two_g), "2G 應在曲線上（驗證倍點公式）");
    }

    #[test]
    fn add_identity_and_inverse() {
        let c = sect163k1();
        let g = base_g(&c);
        // G + O = G、O + G = G
        assert_eq!((&g + &c.infinity()).x().unwrap(), g.x().unwrap());
        assert_eq!((&c.infinity() + &g).y().unwrap(), g.y().unwrap());
        // G + (−G) = O
        assert!((&g + &(-&g)).is_infinity());
    }

    #[test]
    fn add_equal_points_matches_twice() {
        // P == Q 分支：G + G 應等於 twice(G)。
        let c = sect163k1();
        let g = base_g(&c);
        let sum = &g + &g;
        let dbl = g.twice();
        assert_eq!(sum.x().unwrap(), dbl.x().unwrap());
        assert_eq!(sum.y().unwrap(), dbl.y().unwrap());
    }

    #[test]
    fn add_distinct_points_stays_on_curve() {
        // distinct-add 路徑（dx≠0）：3G = 2G + G，驗在曲線上。
        let c = sect163k1();
        let g = base_g(&c);
        let three_g = &g.twice() + &g;
        assert!(!three_g.is_infinity());
        assert!(on_curve(&three_g), "3G 應在曲線上（驗證相異點加法公式）");
        // 3G ≠ G（sanity）
        assert_ne!(
            three_g.x().unwrap().to_big_integer(),
            g.x().unwrap().to_big_integer()
        );
    }

    #[test]
    fn subtract_is_add_negate() {
        let c = sect163k1();
        let g = base_g(&c);
        // G − G = O、G − O = G
        assert!((&g - &g).is_infinity());
        assert_eq!((&g - &c.infinity()).x().unwrap(), g.x().unwrap());
        // 2G − G = G
        let back = &g.twice() - &g;
        assert_eq!(back.x().unwrap(), g.x().unwrap());
        assert_eq!(back.y().unwrap(), g.y().unwrap());
    }

    #[test]
    fn scalar_mul_basics() {
        let c = sect163k1();
        let g = base_g(&c);
        // 0·G = O、k·O = O
        assert!((&g * &BigInteger::from_u32(0)).is_infinity());
        assert!((&c.infinity() * &BigInteger::from_u32(5)).is_infinity());
        // 1·G = G
        assert_eq!((&g * &BigInteger::from_u32(1)).x().unwrap(), g.x().unwrap());
        // 2·G = twice(G)
        assert_eq!(
            (&g * &BigInteger::from_u32(2)).x().unwrap(),
            g.twice().x().unwrap()
        );
        // (−1)·G = −G
        assert_eq!(
            (&g * &BigInteger::from_i32(-1)).y().unwrap(),
            (-&g).y().unwrap()
        );
    }

    #[test]
    fn scalar_mul_order_times_g_is_infinity() {
        // 終極測試：n·G = O（n = sect163k1 群階）。任何體域/倍點/加法錯誤都會讓它失敗。
        let c = sect163k1();
        let g = base_g(&c);
        let n =
            BigInteger::from_str_radix("04000000000000000000020108A2E0CC0D99F8A5EF", 16).unwrap();
        assert!((&g * &n).is_infinity(), "n·G 應為無窮遠點");
    }

    #[test]
    fn point_equality() {
        let c = sect163k1();
        let g = base_g(&c);
        // 同座標 → 相等（重新造一次基點）。
        assert_eq!(g, base_g(&c));
        // 兩個無窮遠點相等。
        assert_eq!(c.infinity(), c.infinity());
        // 無窮遠 ≠ 有限點；G ≠ 2G。
        assert_ne!(g, c.infinity());
        assert_ne!(g, g.twice());
        // 現在點可直接 assert_eq!：G + G == 2G。
        assert_eq!(&g + &g, g.twice());
    }

    #[test]
    fn encode_lengths_and_prefixes() {
        let c = sect163k1();
        let g = base_g(&c);
        let len = c.field_element_encoding_length(); // ⌈163/8⌉ = 21

        // 無窮遠 → 單 byte 0x00。
        assert_eq!(c.infinity().encode(true), alloc::vec![0x00]);

        // 未壓縮：0x04 + X + Y，長度 1+2·len。
        let unc = g.encode(false);
        assert_eq!(unc.len(), 1 + 2 * len);
        assert_eq!(unc[0], 0x04);
        assert_eq!(c.affine_point_encoding_length(false), unc.len());

        // 壓縮：0x02/0x03 + X，長度 1+len；前綴 = y-tilde。
        let comp = g.encode(true);
        assert_eq!(comp.len(), 1 + len);
        assert!(comp[0] == 0x02 || comp[0] == 0x03);
        assert_eq!(c.affine_point_encoding_length(true), comp.len());
        // X 部分：壓縮與未壓縮相同。
        assert_eq!(&comp[1..], &unc[1..=len]);
    }

    #[test]
    fn encode_compressed_prefix_matches_y_tilde() {
        let c = sect163k1();
        let g = base_g(&c);
        // z = y/x 的低位決定 0x02/0x03。
        let (x, y) = (g.x().unwrap(), g.y().unwrap());
        let expected = if (y / x).test_bit_zero() { 0x03 } else { 0x02 };
        assert_eq!(g.encode(true)[0], expected);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let c = sect163k1();
        let g = base_g(&c);
        // 壓縮/未壓縮都 round-trip（壓縮走 decompress → half_trace → 選根）。
        for compressed in [false, true] {
            let decoded = c.decode_point(&g.encode(compressed)).unwrap();
            assert_eq!(decoded, g, "compressed={compressed}");
        }
        // 2G 壓縮 round-trip（另一個 y-tilde）。
        let two_g = g.twice();
        assert_eq!(c.decode_point(&two_g.encode(true)).unwrap(), two_g);
        // 無窮遠。
        assert!(
            c.decode_point(&c.infinity().encode(true))
                .unwrap()
                .is_infinity()
        );
    }
}
