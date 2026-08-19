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
use core::ops::Neg;

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

    // TODO(ec-point)：其餘點運算待實作（對應 bc FpPoint / ECPointBase）：
    //   add / twice(倍點) / subtract / scalar multiply。
    //   affine 加法/倍點公式需要曲線係數 a（self.curve.a()）與體域運算。
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
