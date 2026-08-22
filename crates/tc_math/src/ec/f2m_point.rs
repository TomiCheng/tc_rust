//! Points on binary-field (F2m) short-Weierstrass curves.
//!
//! Corresponds to `F2mPoint` in Bouncy Castle C#. The curve equation over `GF(2ᵐ)`
//! is `y² + xy = x³ + ax² + b` (unlike the Fp form `y² = x³ + ax + b`), so the point
//! arithmetic formulas differ — but the data layout mirrors [`FpPoint`](super::FpPoint)
//! exactly (bc shares the same `ECPointBase` `m_curve`/`m_x`/`m_y`/`m_zs`).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Add, Neg};

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
        F2mPoint { curve, coords: Some((x, y)), zs: Vec::new() }
    }

    /// Returns the point at infinity (the group identity) on `curve`.
    pub fn infinity(curve: Arc<F2mCurve>) -> Self {
        F2mPoint { curve, coords: None, zs: Vec::new() }
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
        assert_eq!(np.y().unwrap().to_big_integer(), BigInteger::from_u32(0b0011)); // y 不變
    }

    #[test]
    fn neg_general_point_and_involution() {
        let c = curve16();
        // P = (x, y)，x≠0 → −P = (x, y+x)。
        let p = c.create_point(BigInteger::from_u32(0b0010), BigInteger::from_u32(0b0111));
        let np = -&p;
        assert_eq!(np.x().unwrap().to_big_integer(), BigInteger::from_u32(0b0010)); // x 不變
        // y + x = 0b0111 ^ 0b0010 = 0b0101
        assert_eq!(np.y().unwrap().to_big_integer(), BigInteger::from_u32(0b0101));
        // 對合：−(−P) = P
        let nnp = -&np;
        assert_eq!(nnp.x().unwrap().to_big_integer(), p.x().unwrap().to_big_integer());
        assert_eq!(nnp.y().unwrap().to_big_integer(), p.y().unwrap().to_big_integer());
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
        assert_ne!(three_g.x().unwrap().to_big_integer(), g.x().unwrap().to_big_integer());
    }
}
