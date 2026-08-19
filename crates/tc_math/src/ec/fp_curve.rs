//! Prime-field elliptic curves.
//!
//! Corresponds to `FpCurve` in Bouncy Castle C# — a short-Weierstrass curve
//! `y^2 = x^3 + ax + b` over the prime field GF(q). Points ([`FpPoint`]) hold an
//! `Arc<FpCurve>` back-reference and are created through the curve.
//!
//! [`FpPoint`]: crate::ec::fp_point::FpPoint

use alloc::sync::Arc;

use crate::big_integer::BigInteger;
use crate::ec::CoordinateSystem;
use crate::ec::fp_field_element::FpFieldElement;
use crate::ec::fp_point::FpPoint;
use crate::ec::point_codec::PointDecodeError;

/// A short-Weierstrass elliptic curve `y^2 = x^3 + ax + b` over GF(q).
///
/// Mirrors `FpCurve`. Holds the field modulus `q` and its reduction residue
/// `r` (computed once and shared with every field element the curve creates),
/// the coefficients `a`, `b`, and the optional group `order` and `cofactor`.
pub struct FpCurve {
    // 體域質數（模數）。
    q: BigInteger,
    // 快速模約簡殘值，算一次、分給每個由本曲線建立的體域元素。
    r: Option<BigInteger>,
    // 曲線係數 a、b（體域元素）。
    a: FpFieldElement,
    b: FpFieldElement,
    // 群階與 cofactor（未必已知）。
    order: Option<BigInteger>,
    cofactor: Option<BigInteger>,
    // 點的座標系。MVP 只支援 Affine（bc 預設是 JacobianModified，等實作 Jacobian
    // 再改預設）。
    coordinate_system: CoordinateSystem,
}

/// Two curves are equal iff they share the same field modulus and coefficients.
///
/// Corresponds to `Equals` in Bouncy Castle (`ECCurve` compares field, `a`,
/// `b`). Configuration such as the coordinate system, order, and cofactor is
/// not part of the mathematical identity and is excluded.
impl PartialEq for FpCurve {
    fn eq(&self, other: &Self) -> bool {
        self.q == other.q && self.a == other.a && self.b == other.b
    }
}

impl Eq for FpCurve {}

impl FpCurve {
    /// Creates the curve `y^2 = x^3 + ax + b` over GF(`q`).
    ///
    /// `a` and `b` are validated to lie in `[0, q)`.
    ///
    /// # Panics
    ///
    /// Panics if `q` is not positive, or if `a`/`b` are out of range.
    pub fn new(
        q: BigInteger,
        a: BigInteger,
        b: BigInteger,
        order: Option<BigInteger>,
        cofactor: Option<BigInteger>,
    ) -> Self {
        assert!(q.sign() > 0, "field modulus q must be positive");
        // 殘值算一次，之後所有體域元素共用（對應 bc AbstractFpCurve 的 m_r）。
        let r = FpFieldElement::calculate_residue(&q);
        let a = Self::make_field_element(&q, a, &r);
        let b = Self::make_field_element(&q, b, &r);
        FpCurve {
            q,
            r,
            a,
            b,
            order,
            cofactor,
            coordinate_system: CoordinateSystem::Affine,
        }
    }

    /// Builds a field element for this curve's field from an integer,
    /// validating `0 <= x < q`.
    ///
    /// Corresponds to `FromBigInteger` in Bouncy Castle.
    ///
    /// # Panics
    ///
    /// Panics if `x` is negative or `>= q`.
    pub fn field_element(&self, x: BigInteger) -> FpFieldElement {
        Self::make_field_element(&self.q, x, &self.r)
    }

    // 共用的建元素邏輯：範圍檢查 + 以共用的 r 建立（bc FromBigInteger 的檢查）。
    fn make_field_element(q: &BigInteger, x: BigInteger, r: &Option<BigInteger>) -> FpFieldElement {
        assert!(
            x.sign() >= 0 && &x < q,
            "value invalid for Fp field element"
        );
        FpFieldElement::new(q.clone(), x, r.clone())
    }

    /// Returns the field modulus `q`.
    pub fn q(&self) -> &BigInteger {
        &self.q
    }

    /// Returns the curve coefficient `a`.
    pub fn a(&self) -> &FpFieldElement {
        &self.a
    }

    /// Returns the curve coefficient `b`.
    pub fn b(&self) -> &FpFieldElement {
        &self.b
    }

    /// Returns the group order `n`, if known.
    pub fn order(&self) -> Option<&BigInteger> {
        self.order.as_ref()
    }

    /// Returns the cofactor `h`, if known.
    pub fn cofactor(&self) -> Option<&BigInteger> {
        self.cofactor.as_ref()
    }

    /// Returns the coordinate system points on this curve use.
    ///
    /// Corresponds to `CoordinateSystem` in Bouncy Castle.
    pub fn coordinate_system(&self) -> CoordinateSystem {
        self.coordinate_system
    }

    /// Returns this curve configured to use `coordinate_system` for its points.
    ///
    /// Corresponds to `Configure().SetCoordinateSystem(...)` in Bouncy Castle.
    /// Note: only [`CoordinateSystem::Affine`] point arithmetic is implemented
    /// so far; other systems will be added later.
    pub fn with_coordinate_system(mut self, coordinate_system: CoordinateSystem) -> Self {
        self.coordinate_system = coordinate_system;
        self
    }

    /// Recovers the point with x-coordinate `x1` and the given y-parity from the
    /// curve equation `y^2 = x^3 + ax + b`.
    ///
    /// `y_tilde` is the low bit of the desired `y` (0 or 1), as carried by a
    /// compressed SEC encoding. Returns `None` if `x1` is not the x-coordinate
    /// of any point on the curve (the right-hand side is not a quadratic
    /// residue).
    ///
    /// Corresponds to `DecompressPoint` in Bouncy Castle. Takes `self` as an
    /// `Arc` so the recovered point can hold a back-reference to the curve.
    pub fn decompress_point(self: &Arc<Self>, y_tilde: u32, x1: BigInteger) -> Option<FpPoint> {
        let x = self.field_element(x1);
        // rhs = x³ + ax + b（Horner：(x² + a)·x + b）
        let rhs = &(&(&x.square() + self.a()) * &x) + self.b();
        let y = rhs.sqrt()?; // None = x 不在曲線上（rhs 非二次剩餘）
        // 選奇偶相符的根：y 最低位 ≠ y_tilde → 換另一個根 −y（q 為奇質數，翻轉奇偶）
        let y = if y.as_ref().test_bit(0) != (y_tilde == 1) {
            -&y
        } else {
            y
        };
        Some(FpPoint::new(Arc::clone(self), x, y))
    }

    /// The byte length of a field-element encoding, `⌈bitlen(q) / 8⌉`.
    ///
    /// Corresponds to `FieldElementEncodingLength` in Bouncy Castle.
    pub fn field_element_encoding_length(&self) -> usize {
        (self.q.bit_length() as usize).div_ceil(8)
    }

    /// Returns `true` if the affine point `(x, y)` satisfies the curve equation
    /// `y^2 = x^3 + ax + b`.
    pub(crate) fn contains_affine(&self, x: &FpFieldElement, y: &FpFieldElement) -> bool {
        // rhs = x³ + ax + b（Horner：(x² + a)·x + b）
        let rhs = &(&(&x.square() + self.a()) * x) + self.b();
        y.square() == rhs
    }

    // 從位元組解析一個座標並確認落在 [0, q)（解不可信輸入，不能讓 field_element panic）。
    fn parse_coordinate(&self, bytes: &[u8]) -> Result<FpFieldElement, PointDecodeError> {
        let v = BigInteger::from_bytes_be_unsigned(bytes);
        if &v >= self.q() {
            return Err(PointDecodeError::CoordinateOutOfRange);
        }
        Ok(self.field_element(v))
    }

    /// Decodes a point from its SEC (X9.62 / SEC 1) encoding.
    ///
    /// Handles the point-at-infinity (`0x00`), compressed (`0x02`/`0x03`),
    /// uncompressed (`0x04`), and hybrid (`0x06`/`0x07`) encodings. Decoded
    /// coordinates are validated to lie on the curve.
    ///
    /// Corresponds to `DecodePoint` in Bouncy Castle. Takes `self` as an `Arc`
    /// so the decoded point can hold its curve back-reference.
    pub fn decode_point(self: &Arc<Self>, encoded: &[u8]) -> Result<FpPoint, PointDecodeError> {
        let len = self.field_element_encoding_length();
        let (&type_byte, rest) = encoded.split_first().ok_or(PointDecodeError::Empty)?;

        match type_byte {
            0x00 => {
                // 無窮遠點:只有前綴 1 byte。
                if rest.is_empty() {
                    Ok(FpPoint::infinity(Arc::clone(self)))
                } else {
                    Err(PointDecodeError::InvalidLength)
                }
            }
            0x02 | 0x03 => {
                // 壓縮:prefix + X（decompress 內含 sqrt 驗證在曲線上）。
                if rest.len() != len {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = BigInteger::from_bytes_be_unsigned(rest);
                if &x >= self.q() {
                    return Err(PointDecodeError::CoordinateOutOfRange);
                }
                let y_tilde = (type_byte & 1) as u32;
                self.decompress_point(y_tilde, x)
                    .ok_or(PointDecodeError::NotOnCurve)
            }
            0x04 => {
                // 未壓縮:prefix + X + Y。
                if rest.len() != 2 * len {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = self.parse_coordinate(&rest[..len])?;
                let y = self.parse_coordinate(&rest[len..])?;
                if !self.contains_affine(&x, &y) {
                    return Err(PointDecodeError::NotOnCurve);
                }
                Ok(FpPoint::new(Arc::clone(self), x, y))
            }
            0x06 | 0x07 => {
                // 混合:同未壓縮，前綴另帶 Y 奇偶（0x07 = 奇）。
                if rest.len() != 2 * len {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = self.parse_coordinate(&rest[..len])?;
                let y = self.parse_coordinate(&rest[len..])?;
                if y.as_ref().test_bit(0) != (type_byte == 0x07) {
                    return Err(PointDecodeError::InconsistentHybridY);
                }
                if !self.contains_affine(&x, &y) {
                    return Err(PointDecodeError::NotOnCurve);
                }
                Ok(FpPoint::new(Arc::clone(self), x, y))
            }
            other => Err(PointDecodeError::UnknownEncoding(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // secp256k1: y^2 = x^3 + 7 over GF(p).
    fn secp256k1() -> FpCurve {
        let p = BigInteger::from_str_radix(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap();
        FpCurve::new(
            p,
            BigInteger::from_u32(0),
            BigInteger::from_u32(7),
            None,
            None,
        )
    }

    #[test]
    fn new_sets_coefficients() {
        let c = secp256k1();
        assert!(c.a().is_zero());
        assert_eq!(c.b().as_ref(), &BigInteger::from_u32(7));
        assert_eq!(c.coordinate_system(), CoordinateSystem::Affine);
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

    #[test]
    fn decompress_recovers_point() {
        let curve = curve17();
        // x=5 → G=(5,1)。y_tilde=1（y 奇）→ (5,1)。
        let p = curve.decompress_point(1, BigInteger::from_u32(5)).unwrap();
        assert_eq!(p.x().unwrap().as_ref(), &BigInteger::from_u32(5));
        assert_eq!(p.y().unwrap().as_ref(), &BigInteger::from_u32(1));
        // y_tilde=0（y 偶）→ 另一根 (5,16)。
        let q = curve.decompress_point(0, BigInteger::from_u32(5)).unwrap();
        assert_eq!(q.y().unwrap().as_ref(), &BigInteger::from_u32(16));
    }

    #[test]
    fn encoding_length_is_ceil_bits_over_8() {
        assert_eq!(curve17().field_element_encoding_length(), 1); // 17 → 5 bits → 1 byte
        assert_eq!(secp256k1().field_element_encoding_length(), 32); // 256 bits → 32 bytes
    }

    #[test]
    fn contains_affine_checks_curve_equation() {
        let curve = curve17();
        let x = curve.field_element(BigInteger::from_u32(5));
        // (5,1) 在曲線上、(5,2) 不在。
        assert!(curve.contains_affine(&x, &curve.field_element(BigInteger::from_u32(1))));
        assert!(!curve.contains_affine(&x, &curve.field_element(BigInteger::from_u32(2))));
    }

    #[test]
    fn decode_infinity_and_errors() {
        let curve = curve17();
        assert!(curve.decode_point(&[0x00]).unwrap().is_infinity());
        assert!(matches!(curve.decode_point(&[0x00, 0x00]), Err(PointDecodeError::InvalidLength)));
        assert!(matches!(curve.decode_point(&[]), Err(PointDecodeError::Empty)));
        assert!(matches!(curve.decode_point(&[0x04, 5]), Err(PointDecodeError::InvalidLength)));
        assert!(matches!(curve.decode_point(&[0x09, 5]), Err(PointDecodeError::UnknownEncoding(9))));
    }

    #[test]
    fn decode_compressed() {
        let curve = curve17();
        // 0x03（y 奇）+ X=5 → (5,1)。
        let p = curve.decode_point(&[0x03, 5]).unwrap();
        assert_eq!(p.x().unwrap().as_ref(), &BigInteger::from_u32(5));
        assert_eq!(p.y().unwrap().as_ref(), &BigInteger::from_u32(1));
        // 0x02（y 偶）→ 另一根 (5,16)。
        assert_eq!(
            curve.decode_point(&[0x02, 5]).unwrap().y().unwrap().as_ref(),
            &BigInteger::from_u32(16)
        );
        // x=1：rhs=5 非二次剩餘 → NotOnCurve。
        assert!(matches!(curve.decode_point(&[0x02, 1]), Err(PointDecodeError::NotOnCurve)));
    }

    #[test]
    fn decode_uncompressed_and_hybrid() {
        let curve = curve17();
        // 0x04 + X + Y = (5,1)。
        let p = curve.decode_point(&[0x04, 5, 1]).unwrap();
        assert_eq!(p.x().unwrap().as_ref(), &BigInteger::from_u32(5));
        assert_eq!(p.y().unwrap().as_ref(), &BigInteger::from_u32(1));
        // 混合 0x07（y 奇）與 (5,1) 一致 → ok。
        assert!(curve.decode_point(&[0x07, 5, 1]).is_ok());
        // 混合 0x06（宣稱 y 偶）但 y=1 奇 → InconsistentHybridY。
        assert!(matches!(
            curve.decode_point(&[0x06, 5, 1]),
            Err(PointDecodeError::InconsistentHybridY)
        ));
        // 不在曲線 (5,2) → NotOnCurve。
        assert!(matches!(curve.decode_point(&[0x04, 5, 2]), Err(PointDecodeError::NotOnCurve)));
        // 座標越界 x=17(=q) → CoordinateOutOfRange。
        assert!(matches!(
            curve.decode_point(&[0x04, 17, 1]),
            Err(PointDecodeError::CoordinateOutOfRange)
        ));
    }

    #[test]
    fn decompress_rejects_non_curve_x() {
        let curve = curve17();
        // x=1：rhs = 1+2+2 = 5，非二次剩餘 → None。
        assert!(curve.decompress_point(0, BigInteger::from_u32(1)).is_none());
    }

    #[test]
    fn with_coordinate_system_overrides_default() {
        let c = secp256k1().with_coordinate_system(CoordinateSystem::JacobianModified);
        assert_eq!(c.coordinate_system(), CoordinateSystem::JacobianModified);
    }

    #[test]
    fn field_element_builds_element() {
        let c = secp256k1();
        let e = c.field_element(BigInteger::from_u32(5));
        assert_eq!(e.as_ref(), &BigInteger::from_u32(5));
    }

    #[test]
    #[should_panic(expected = "value invalid")]
    fn field_element_rejects_out_of_range() {
        let c = secp256k1();
        c.field_element(c.q().clone()); // x == q 越界
    }
}
