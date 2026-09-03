//! Binary-field (F2m) short-Weierstrass curves.
//!
//! Corresponds to `F2mCurve` in Bouncy Castle C#. The curve `y² + xy = x³ + ax² + b`
//! lives over `GF(2ᵐ)`; it owns the shared [`F2mField`] definition (as an `Arc`, so
//! its coefficients and every point share one copy) plus the coefficients `a`, `b`.
//!
//! Mirrors [`FpCurve`](super::FpCurve): the same shape, but the field is an
//! `Arc<F2mField>` instead of the prime modulus `q` and residue `r`.

use alloc::sync::Arc;
use alloc::vec;

use crate::big_integer::BigInteger;
use crate::binpoly::BinaryPoly;
use crate::ec::coordinate_system::CoordinateSystem;
use crate::ec::f2m_field::F2mField;
use crate::ec::f2m_field_element::F2mFieldElement;
use crate::ec::f2m_point::F2mPoint;
use crate::ec::point_codec::PointDecodeError;

/// A short-Weierstrass elliptic curve `y² + xy = x³ + ax² + b` over `GF(2ᵐ)`.
///
/// Mirrors bc `F2mCurve`. Construction and point operations are added later; this is
/// the data layout only.
pub struct F2mCurve {
    // 共享體域定義（取代 FpCurve 的 q + r）。a/b 與 point 都 clone 這個 Arc。
    field: Arc<F2mField>,
    // Weierstrass 係數 a、b（體域元素，與 field 同源）。
    a: F2mFieldElement,
    b: F2mFieldElement,
    // 群階與 cofactor（未必已知）。
    order: Option<BigInteger>,
    cofactor: Option<BigInteger>,
    // 點座標系。bc F2m 預設 COORD_LAMBDA_PROJECTIVE；MVP 比照 FpCurve 先走 Affine。
    coordinate_system: CoordinateSystem,
}

impl F2mCurve {
    /// Creates the curve `y² + xy = x³ + ax² + b` over `GF(2ᵐ)` reduced by the
    /// trinomial `xᵐ + xᵏ + 1`. Mirrors bc's trinomial `F2mCurve` constructor.
    ///
    /// # Panics
    ///
    /// Panics if `a` or `b` is negative or has bit length `> m` (see
    /// [`create_field_element`](Self::create_field_element)).
    pub fn trinomial(
        m: usize,
        k: usize,
        a: BigInteger,
        b: BigInteger,
        order: Option<BigInteger>,
        cofactor: Option<BigInteger>,
    ) -> Self {
        Self::from_field(Arc::new(F2mField::trinomial(m, k)), a, b, order, cofactor)
    }

    /// Creates the curve over `GF(2ᵐ)` reduced by the pentanomial
    /// `xᵐ + xᵏ³ + xᵏ² + xᵏ¹ + 1`. Mirrors bc's pentanomial `F2mCurve` constructor.
    ///
    /// # Panics
    ///
    /// Panics if `a` or `b` is negative or has bit length `> m`.
    // 8 個參數忠實對應 bc F2mCurve 的五項式建構子（m,k1,k2,k3,a,b,order,cofactor）。
    #[allow(clippy::too_many_arguments)]
    pub fn pentanomial(
        m: usize,
        k1: usize,
        k2: usize,
        k3: usize,
        a: BigInteger,
        b: BigInteger,
        order: Option<BigInteger>,
        cofactor: Option<BigInteger>,
    ) -> Self {
        Self::from_field(
            Arc::new(F2mField::pentanomial(m, k1, k2, k3)),
            a,
            b,
            order,
            cofactor,
        )
    }

    /// Shared construction over an already-built field: builds the coefficient
    /// elements and fixes the (affine, for now) coordinate system.
    fn from_field(
        field: Arc<F2mField>,
        a: BigInteger,
        b: BigInteger,
        order: Option<BigInteger>,
        cofactor: Option<BigInteger>,
    ) -> Self {
        let a = Self::make_field_element(&field, a);
        let b = Self::make_field_element(&field, b);
        F2mCurve {
            field,
            a,
            b,
            order,
            cofactor,
            coordinate_system: CoordinateSystem::Affine,
        }
    }

    /// Builds a field element of this curve's field from an integer, validating
    /// `0 <= x` and `bit_length(x) <= m`. Corresponds to bc `FromBigInteger`; named
    /// `create_field_element` (like [`FpCurve`](super::FpCurve)) so it reads as the
    /// `&self` factory it is, rather than a getter or a `from_*` constructor.
    ///
    /// # Panics
    ///
    /// Panics if `x` is negative or has bit length `> m`.
    pub fn create_field_element(&self, x: BigInteger) -> F2mFieldElement {
        Self::make_field_element(&self.field, x)
    }

    // 共用建元素邏輯：範圍檢查 + BigInteger → 定長 LE u64 limbs（bc FromBigInteger →
    // Nat.FromBigInteger64）。
    fn make_field_element(field: &Arc<F2mField>, x: BigInteger) -> F2mFieldElement {
        assert!(
            x.sign() >= 0 && (x.bit_length() as usize) <= field.m(),
            "value invalid for F2m field element"
        );
        // 寫進 size(m) 個 limb 的緩衝：低位在前，高位自然補零（bit_length<=m 保證 fits）。
        let mut limbs = vec![0u64; field.size()];
        x.to_u64_le_unsigned_into(&mut limbs);
        F2mFieldElement::new(Arc::clone(field), BinaryPoly::from_limbs(limbs))
    }

    /// Returns the curve coefficient `a`.
    pub fn a(&self) -> &F2mFieldElement {
        &self.a
    }

    /// Returns the curve coefficient `b`.
    pub fn b(&self) -> &F2mFieldElement {
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

    /// Returns the field degree `m` (= field size in bits). Corresponds to bc
    /// `FieldSize`.
    pub fn field_size(&self) -> usize {
        self.field.m()
    }

    /// The byte length of a field-element encoding, `⌈m / 8⌉`.
    ///
    /// Corresponds to `FieldElementEncodingLength` in bc.
    pub fn field_element_encoding_length(&self) -> usize {
        self.field.m().div_ceil(8)
    }

    /// The byte length of an affine point's SEC encoding: `1 + len` compressed,
    /// `1 + 2*len` uncompressed (`len` = field-element encoding length).
    ///
    /// Corresponds to `GetAffinePointEncodingLength` in bc.
    pub fn affine_point_encoding_length(&self, compressed: bool) -> usize {
        let len = self.field_element_encoding_length();
        if compressed { 1 + len } else { 1 + 2 * len }
    }

    /// Returns the point coordinate system in use.
    pub fn coordinate_system(&self) -> CoordinateSystem {
        self.coordinate_system
    }

    /// Returns the point at infinity (the group identity) on this curve.
    ///
    /// Takes `self` as an `Arc` so the point can hold a back-reference to the curve.
    pub fn infinity(self: &Arc<Self>) -> F2mPoint {
        F2mPoint::infinity(Arc::clone(self))
    }

    /// Creates the affine point `(x, y)` on this curve from integer coordinates.
    ///
    /// Does not verify the point lies on the curve (a separate check). Corresponds to
    /// `CreatePoint` in bc. Takes `self` as an `Arc` so the point can back-reference
    /// the curve.
    ///
    /// # Panics
    ///
    /// Panics if either coordinate is out of range (see [`create_field_element`]).
    ///
    /// [`create_field_element`]: Self::create_field_element
    pub fn create_point(self: &Arc<Self>, x: BigInteger, y: BigInteger) -> F2mPoint {
        F2mPoint::new(
            Arc::clone(self),
            self.create_field_element(x),
            self.create_field_element(y),
        )
    }

    /// Returns `true` if the affine point `(x, y)` satisfies `y² + xy = x³ + ax² + b`.
    pub(crate) fn contains_affine(&self, x: &F2mFieldElement, y: &F2mFieldElement) -> bool {
        let lhs = &y.square() + &(x * y); // y² + xy
        let x2 = x.square();
        let rhs = &(&(&x2 * x) + &(self.a() * &x2)) + self.b(); // x³ + a·x² + b
        lhs == rhs
    }

    /// Solves `z² + z = beta` (X9.62 D.1.6), returning a solution or `None` if none
    /// exists (the other solution is `z + 1`). Corresponds to bc
    /// `SolveQuadraticEquation`.
    ///
    /// # Panics
    ///
    /// Panics for even `m` (the even-`m` fallback is not ported; all sect curves have
    /// odd `m`).
    fn solve_quadratic(&self, beta: &F2mFieldElement) -> Option<F2mFieldElement> {
        assert!(
            self.field.m() & 1 == 1,
            "solve_quadratic: even m not supported"
        );
        let r = beta.half_trace();
        // r²+r == beta 才是解；Tr(beta)≠0 時 half_trace 不滿足 → 無解。
        if (&(&r.square() + &r) + beta).is_zero() {
            Some(r)
        } else {
            None
        }
    }

    /// Recovers an affine point from its `x`-coordinate and the compression parity bit
    /// `y_tilde`. Corresponds to bc `DecompressPoint` (affine branch): with `x = 0`,
    /// `y = √b`; otherwise solve `z² + z = b/x² + a + x` and take `y = z·x`, picking
    /// the root whose parity matches `y_tilde`.
    ///
    /// Takes `self` as an `Arc` so the recovered point can back-reference the curve.
    pub fn decompress_point(self: &Arc<Self>, y_tilde: u32, x1: BigInteger) -> Option<F2mPoint> {
        let xp = self.create_field_element(x1);
        let yp = if xp.is_zero() {
            self.b().sqrt() // x = 0 → y = √b（F2m 平方根必存在）
        } else {
            // beta = b/x² + a + x
            let beta = &(&(&xp.square().invert() * self.b()) + self.a()) + &xp;
            let mut z = self.solve_quadratic(&beta)?; // None → x 不在曲線上
            // 選奇偶相符的根：z 低位 ≠ y_tilde → 換另一解 z+1
            if z.test_bit_zero() != (y_tilde == 1) {
                z = z.add_one();
            }
            &z * &xp // affine：y = z·x
        };
        Some(F2mPoint::new(Arc::clone(self), xp, yp))
    }

    // 從位元組解析座標並確認 bit_length ≤ m（解不可信輸入，不能讓 create_field_element panic）。
    fn parse_coordinate(&self, bytes: &[u8]) -> Result<F2mFieldElement, PointDecodeError> {
        let v = BigInteger::from_bytes_be_unsigned(bytes);
        if v.bit_length() as usize > self.field.m() {
            return Err(PointDecodeError::CoordinateOutOfRange);
        }
        Ok(self.create_field_element(v))
    }

    /// Decodes a point from its SEC (X9.62 / SEC 1) encoding: infinity (`0x00`),
    /// compressed (`0x02`/`0x03`), uncompressed (`0x04`), and hybrid (`0x06`/`0x07`).
    /// Decoded coordinates are validated to lie on the curve.
    ///
    /// Corresponds to `DecodePoint` in bc. Takes `self` as an `Arc` for the back-ref.
    pub fn decode_point(self: &Arc<Self>, encoded: &[u8]) -> Result<F2mPoint, PointDecodeError> {
        let len = self.field_element_encoding_length();
        let (&type_byte, rest) = encoded.split_first().ok_or(PointDecodeError::Empty)?;

        match type_byte {
            0x00 => {
                if rest.is_empty() {
                    Ok(F2mPoint::infinity(Arc::clone(self)))
                } else {
                    Err(PointDecodeError::InvalidLength)
                }
            }
            0x02 | 0x03 => {
                // 壓縮：prefix + X（decompress 內含 half_trace 驗證在曲線上）。
                if rest.len() != len {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = BigInteger::from_bytes_be_unsigned(rest);
                if x.bit_length() as usize > self.field.m() {
                    return Err(PointDecodeError::CoordinateOutOfRange);
                }
                let y_tilde = (type_byte & 1) as u32;
                self.decompress_point(y_tilde, x)
                    .ok_or(PointDecodeError::NotOnCurve)
            }
            0x04 => {
                // 未壓縮：prefix + X + Y。
                if rest.len() != 2 * len {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = self.parse_coordinate(&rest[..len])?;
                let y = self.parse_coordinate(&rest[len..])?;
                if !self.contains_affine(&x, &y) {
                    return Err(PointDecodeError::NotOnCurve);
                }
                Ok(F2mPoint::new(Arc::clone(self), x, y))
            }
            0x06 | 0x07 => {
                // 混合：同未壓縮，前綴另帶 y-tilde（0x07 = 1）。
                if rest.len() != 2 * len {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = self.parse_coordinate(&rest[..len])?;
                let y = self.parse_coordinate(&rest[len..])?;
                // F2m y-tilde：x=0 → false，否則 (y/x) 低位。
                let y_tilde = !x.is_zero() && (&y / &x).test_bit_zero();
                if y_tilde != (type_byte == 0x07) {
                    return Err(PointDecodeError::InconsistentHybridY);
                }
                if !self.contains_affine(&x, &y) {
                    return Err(PointDecodeError::NotOnCurve);
                }
                Ok(F2mPoint::new(Arc::clone(self), x, y))
            }
            other => Err(PointDecodeError::UnknownEncoding(other)),
        }
    }
}

/// Two curves are equal iff they share the same field and coefficients.
///
/// Corresponds to bc `ECCurve.Equals` (field, `a`, `b`). Coordinate system, order,
/// and cofactor are configuration, not mathematical identity, so they are excluded.
impl PartialEq for F2mCurve {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.a == other.a && self.b == other.b
    }
}

impl Eq for F2mCurve {}

impl core::fmt::Debug for F2mCurve {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("F2mCurve")
            .field("m", &self.field.m())
            .field("a", &self.a.to_big_integer())
            .field("b", &self.b.to_big_integer())
            .finish()
    }
}

/// Hashes the field and coefficients (matching [`PartialEq`]).
impl core::hash::Hash for F2mCurve {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.field.hash(state);
        self.a.hash(state);
        self.b.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trinomial_curve_builds_coefficients() {
        // GF(2^233)（sect233 三項式 x^233+x^74+1）；a=1、b 任意值。
        let c = F2mCurve::trinomial(
            233,
            74,
            BigInteger::from_u32(1),
            BigInteger::from_u32(0x1234_5678),
            None,
            None,
        );
        assert_eq!(c.field_size(), 233);
        assert_eq!(c.a().to_big_integer(), BigInteger::from_u32(1));
        assert_eq!(c.b().to_big_integer(), BigInteger::from_u32(0x1234_5678));
        assert!(c.order().is_none() && c.cofactor().is_none());
        assert_eq!(c.coordinate_system(), CoordinateSystem::Affine);
    }

    #[test]
    fn pentanomial_curve_builds() {
        // sect163k1 五項式 x^163+x^7+x^6+x^3+1，Koblitz a=1、b=1。
        let c = F2mCurve::pentanomial(
            163,
            3,
            6,
            7,
            BigInteger::from_u32(1),
            BigInteger::from_u32(1),
            None,
            None,
        );
        assert_eq!(c.a().to_big_integer(), BigInteger::from_u32(1));
        assert_eq!(c.b().to_big_integer(), BigInteger::from_u32(1));
    }

    #[test]
    fn create_field_element_roundtrips() {
        let c = F2mCurve::trinomial(
            233,
            74,
            BigInteger::from_u32(1),
            BigInteger::from_u32(1),
            None,
            None,
        );
        let e = c.create_field_element(BigInteger::from_u64(0x0102_0304_0506_0708));
        assert_eq!(
            e.to_big_integer(),
            BigInteger::from_u64(0x0102_0304_0506_0708)
        );
    }

    #[test]
    #[should_panic(expected = "value invalid")]
    fn create_field_element_rejects_too_large() {
        let c = F2mCurve::trinomial(
            4,
            1,
            BigInteger::from_u32(1),
            BigInteger::from_u32(1),
            None,
            None,
        );
        // bit_length 5 > m=4 → panic
        c.create_field_element(BigInteger::from_u32(0b1_0000));
    }

    #[test]
    fn infinity_and_create_point() {
        let c = Arc::new(F2mCurve::trinomial(
            4,
            1,
            BigInteger::from_u32(0),
            BigInteger::from_u32(1),
            None,
            None,
        ));
        assert!(c.infinity().is_infinity());

        let p = c.create_point(BigInteger::from_u32(0b0010), BigInteger::from_u32(0b0011));
        assert!(!p.is_infinity());
        assert_eq!(
            p.x().unwrap().to_big_integer(),
            BigInteger::from_u32(0b0010)
        );
        assert_eq!(
            p.y().unwrap().to_big_integer(),
            BigInteger::from_u32(0b0011)
        );
        assert!(Arc::ptr_eq(p.curve(), &c)); // 點回指同一曲線
    }

    #[test]
    fn curve_equality_compares_field_and_coeffs() {
        let mk = |b: u32| {
            F2mCurve::trinomial(
                233,
                74,
                BigInteger::from_u32(1),
                BigInteger::from_u32(b),
                None,
                None,
            )
        };
        assert_eq!(mk(7), mk(7));
        assert_ne!(mk(7), mk(8)); // 係數不同
        // 不同體域 → 不等。
        let other = F2mCurve::pentanomial(
            163,
            3,
            6,
            7,
            BigInteger::from_u32(1),
            BigInteger::from_u32(7),
            None,
            None,
        );
        assert_ne!(mk(7), other);
    }

    #[test]
    fn decode_errors() {
        let c = Arc::new(F2mCurve::pentanomial(
            163,
            3,
            6,
            7,
            BigInteger::from_u32(1),
            BigInteger::from_u32(1),
            None,
            None,
        ));
        assert_eq!(c.decode_point(&[]), Err(PointDecodeError::Empty));
        // 壓縮長度錯（163 → len 21，這裡只給 1 byte X）。
        assert_eq!(
            c.decode_point(&[0x02, 0x01]),
            Err(PointDecodeError::InvalidLength)
        );
        // 未知前綴。
        assert_eq!(
            c.decode_point(&[0x09]),
            Err(PointDecodeError::UnknownEncoding(0x09))
        );
        // 0x00 後多帶資料 → 長度錯。
        assert_eq!(
            c.decode_point(&[0x00, 0x00]),
            Err(PointDecodeError::InvalidLength)
        );
    }
}
