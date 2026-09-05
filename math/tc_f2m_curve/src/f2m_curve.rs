//! `GF(2^m)` 上的短 Weierstrass 曲線。
//!
//! 曲線方程為 `y^2 + xy = x^3 + ax^2 + b`。本檔保留舊 `tc_ec` 的 affine
//! 公式與 SEC 點編解碼語意，但元素表示從一開始便由 `P` 靜態分派。

use alloc::sync::Arc;

use tc_bigint::{BigUint, BitOps};
use tc_binpoly::{BinPolyError, BinaryPoly};
use tc_ec_core::{CoordinateSystem, PointDecodeError};

use crate::{F2mField, F2mFieldElement, F2mPoint, F2mPolynomial};

/// `GF(2^m)` 上的二元短 Weierstrass 曲線。
pub struct F2mCurve<P: F2mPolynomial = BinaryPoly> {
    field: Arc<F2mField>,
    a: F2mFieldElement<P>,
    b: F2mFieldElement<P>,
    order: Option<BigUint>,
    cofactor: Option<BigUint>,
    coordinate_system: CoordinateSystem,
}

impl<P: F2mPolynomial> F2mCurve<P> {
    /// 以三項式 `x^m + x^k + 1` 建立曲線。
    pub fn trinomial(
        m: usize,
        k: usize,
        a: BigUint,
        b: BigUint,
        order: Option<BigUint>,
        cofactor: Option<BigUint>,
    ) -> Result<Self, BinPolyError> {
        Self::from_field(Arc::new(F2mField::trinomial(m, k)?), a, b, order, cofactor)
    }

    /// 以五項式 `x^m + x^k3 + x^k2 + x^k1 + 1` 建立曲線。
    #[allow(clippy::too_many_arguments)]
    pub fn pentanomial(
        m: usize,
        k1: usize,
        k2: usize,
        k3: usize,
        a: BigUint,
        b: BigUint,
        order: Option<BigUint>,
        cofactor: Option<BigUint>,
    ) -> Result<Self, BinPolyError> {
        Self::from_field(
            Arc::new(F2mField::pentanomial(m, k1, k2, k3)?),
            a,
            b,
            order,
            cofactor,
        )
    }

    fn from_field(
        field: Arc<F2mField>,
        a: BigUint,
        b: BigUint,
        order: Option<BigUint>,
        cofactor: Option<BigUint>,
    ) -> Result<Self, BinPolyError> {
        // 先以零建值可提早驗證 `FixedBinaryPoly<N>` 的 N 是否符合 m。
        P::zero(field.multiplier().clone())?;
        let a = F2mFieldElement::from_big_uint(Arc::clone(&field), &a);
        let b = F2mFieldElement::from_big_uint(Arc::clone(&field), &b);
        Ok(Self {
            field,
            a,
            b,
            order,
            cofactor,
            coordinate_system: CoordinateSystem::Affine,
        })
    }

    /// 共享的二元體定義。
    pub fn field(&self) -> &Arc<F2mField> {
        &self.field
    }

    /// 從非負整數建立同一體域的元素。
    pub fn create_field_element(&self, value: BigUint) -> F2mFieldElement<P> {
        F2mFieldElement::from_big_uint(Arc::clone(&self.field), &value)
    }

    /// 曲線係數 `a`。
    pub fn a(&self) -> &F2mFieldElement<P> {
        &self.a
    }

    /// 曲線係數 `b`。
    pub fn b(&self) -> &F2mFieldElement<P> {
        &self.b
    }

    /// 基點子群階。
    pub fn order(&self) -> Option<&BigUint> {
        self.order.as_ref()
    }

    /// Cofactor。
    pub fn cofactor(&self) -> Option<&BigUint> {
        self.cofactor.as_ref()
    }

    /// 體域度數 `m`。
    pub fn field_size(&self) -> usize {
        self.field.m()
    }

    /// 單一體元素的 SEC 固定編碼長度。
    pub fn field_element_encoding_length(&self) -> usize {
        self.field.m().div_ceil(8)
    }

    /// Affine 點的 SEC 編碼長度。
    pub fn affine_point_encoding_length(&self, compressed: bool) -> usize {
        let length = self.field_element_encoding_length();
        if compressed {
            length + 1
        } else {
            length * 2 + 1
        }
    }

    /// 目前使用的座標系。
    pub const fn coordinate_system(&self) -> CoordinateSystem {
        self.coordinate_system
    }

    /// 同一條曲線上的無窮遠點。
    pub fn infinity(self: &Arc<Self>) -> F2mPoint<P> {
        F2mPoint::infinity(Arc::clone(self))
    }

    /// 從 affine 整數座標建立點；不額外驗證是否在曲線上。
    pub fn create_point(self: &Arc<Self>, x: BigUint, y: BigUint) -> F2mPoint<P> {
        F2mPoint::new(
            Arc::clone(self),
            self.create_field_element(x),
            self.create_field_element(y),
        )
    }

    /// 檢查 affine 座標是否滿足曲線方程。
    pub(crate) fn contains_affine(&self, x: &F2mFieldElement<P>, y: &F2mFieldElement<P>) -> bool {
        let lhs = &y.square() + &(x * y);
        let x2 = x.square();
        let rhs = &(&(&x2 * x) + &(self.a() * &x2)) + self.b();
        lhs == rhs
    }

    /// 解 `z^2 + z = beta`；本次兩條 SEC 曲線的 m 都是奇數，可使用 half-trace。
    fn solve_quadratic(&self, beta: &F2mFieldElement<P>) -> Option<F2mFieldElement<P>> {
        assert!(self.field.m() & 1 == 1, "even m is not supported yet");
        let root = beta.half_trace();
        if (&(&root.square() + &root) + beta).is_zero() {
            Some(root)
        } else {
            None
        }
    }

    /// 由 X 座標與 SEC y-tilde 位元還原 affine 點。
    pub fn decompress_point(self: &Arc<Self>, y_tilde: u8, x: BigUint) -> Option<F2mPoint<P>> {
        let x = self.create_field_element(x);
        let y = if x.is_zero() {
            self.b().sqrt()
        } else {
            let beta = &(&(&x.square().invert() * self.b()) + self.a()) + &x;
            let mut z = self.solve_quadratic(&beta)?;
            if z.test_bit_zero() != (y_tilde == 1) {
                z = z.add_one();
            }
            &z * &x
        };
        Some(F2mPoint::new(Arc::clone(self), x, y))
    }

    fn parse_coordinate(&self, bytes: &[u8]) -> Result<F2mFieldElement<P>, PointDecodeError> {
        let value = BigUint::from_be_bytes(bytes);
        if value.bit_length() > self.field.m() {
            return Err(PointDecodeError::CoordinateOutOfRange);
        }
        Ok(self.create_field_element(value))
    }

    /// 解碼 SEC infinity、compressed、uncompressed 與 hybrid 點格式。
    pub fn decode_point(self: &Arc<Self>, encoded: &[u8]) -> Result<F2mPoint<P>, PointDecodeError> {
        let length = self.field_element_encoding_length();
        let (&tag, rest) = encoded.split_first().ok_or(PointDecodeError::Empty)?;
        match tag {
            0x00 if rest.is_empty() => Ok(self.infinity()),
            0x00 => Err(PointDecodeError::InvalidLength),
            0x02 | 0x03 => {
                if rest.len() != length {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = BigUint::from_be_bytes(rest);
                if x.bit_length() > self.field.m() {
                    return Err(PointDecodeError::CoordinateOutOfRange);
                }
                self.decompress_point(tag & 1, x)
                    .ok_or(PointDecodeError::NotOnCurve)
            }
            0x04 => {
                if rest.len() != length * 2 {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = self.parse_coordinate(&rest[..length])?;
                let y = self.parse_coordinate(&rest[length..])?;
                if !self.contains_affine(&x, &y) {
                    return Err(PointDecodeError::NotOnCurve);
                }
                Ok(F2mPoint::new(Arc::clone(self), x, y))
            }
            0x06 | 0x07 => {
                if rest.len() != length * 2 {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = self.parse_coordinate(&rest[..length])?;
                let y = self.parse_coordinate(&rest[length..])?;
                let y_tilde = !x.is_zero() && (&y / &x).test_bit_zero();
                if y_tilde != (tag == 0x07) {
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

impl<P: F2mPolynomial> PartialEq for F2mCurve<P> {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.a == other.a && self.b == other.b
    }
}

impl<P: F2mPolynomial> Eq for F2mCurve<P> {}

impl<P: F2mPolynomial> core::fmt::Debug for F2mCurve<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("F2mCurve")
            .field("m", &self.field.m())
            .field("a", &self.a.to_big_uint())
            .field("b", &self.b.to_big_uint())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_binpoly::FixedBinaryPoly;

    #[test]
    fn constructors_validate_fixed_width_and_coefficients() {
        assert!(matches!(
            F2mCurve::<FixedBinaryPoly<4>>::trinomial(
                163,
                7,
                BigUint::from(1_u8),
                BigUint::from(1_u8),
                None,
                None,
            ),
            Err(BinPolyError::InvalidLength { .. })
        ));

        let curve = F2mCurve::<FixedBinaryPoly<4>>::trinomial(
            233,
            74,
            BigUint::from(0_u8),
            BigUint::from(1_u8),
            None,
            None,
        )
        .unwrap();
        assert_eq!(curve.field_size(), 233);
        assert_eq!(curve.a().to_big_uint(), BigUint::from(0_u8));
        assert_eq!(curve.b().to_big_uint(), BigUint::from(1_u8));
    }
}
