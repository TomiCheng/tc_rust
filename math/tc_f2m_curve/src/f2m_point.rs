//! 二元擴張體曲線點。
//!
//! 本次只實作 affine 座標；其群運算與舊 `tc_ec` 以及 BC 的 affine 分支一致。
//! `P` 決定體元素底層多項式表示，`B` 決定 SEC 座標與純量整數表示；點公式
//! 本身不依賴任一具體後端。

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Add, Mul, Neg, Sub};

use tc_bigint::BigUint;
use tc_binpoly::{BinaryPoly, BinaryPolyOps};
use tc_ec_core::CoordinateSystem;

use crate::{F2mCurve, F2mFieldElement, F2mInteger, F2mPolynomial};

/// [`F2mCurve`] 上的 affine 點；`coords == None` 代表無窮遠點。
#[derive(Clone)]
pub struct F2mPoint<P: BinaryPolyOps = BinaryPoly, B: F2mInteger = BigUint> {
    curve: Arc<F2mCurve<P, B>>,
    coords: Option<(F2mFieldElement<P>, F2mFieldElement<P>)>,
}

impl<P: F2mPolynomial, B: F2mInteger> F2mPoint<P, B> {
    /// 建立 affine 點；不額外驗證曲線方程。
    pub fn new(curve: Arc<F2mCurve<P, B>>, x: F2mFieldElement<P>, y: F2mFieldElement<P>) -> Self {
        Self {
            curve,
            coords: Some((x, y)),
        }
    }

    /// 建立群單位點。
    pub fn infinity(curve: Arc<F2mCurve<P, B>>) -> Self {
        Self {
            curve,
            coords: None,
        }
    }

    /// 點所屬曲線。
    pub fn curve(&self) -> &Arc<F2mCurve<P, B>> {
        &self.curve
    }

    /// 是否為無窮遠點。
    pub fn is_infinity(&self) -> bool {
        self.coords.is_none()
    }

    /// Affine X 座標。
    pub fn x(&self) -> Option<&F2mFieldElement<P>> {
        self.coords.as_ref().map(|(x, _)| x)
    }

    /// Affine Y 座標。
    pub fn y(&self) -> Option<&F2mFieldElement<P>> {
        self.coords.as_ref().map(|(_, y)| y)
    }

    /// Affine 已是正規化表示。
    pub fn normalize(&self) -> Self {
        self.clone()
    }

    /// 檢查點是否滿足曲線方程與已知群階。
    pub fn is_valid(&self) -> bool {
        let Some((x, y)) = &self.coords else {
            return true;
        };
        if !self.curve.contains_affine(x, y) {
            return false;
        }
        self.curve
            .order()
            .is_none_or(|order| self.mul_double_and_add(order).is_infinity())
    }

    /// SEC 1 / X9.62 點編碼。
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let Some((x, y)) = &self.coords else {
            return alloc::vec![0x00];
        };
        let length = self.curve.field_element_encoding_length();
        let x_bytes = fixed_be(&x.to_integer::<B>(), length);
        if compressed {
            let tag = if Self::compression_y_tilde(x, y) {
                0x03
            } else {
                0x02
            };
            let mut encoded = Vec::with_capacity(length + 1);
            encoded.push(tag);
            encoded.extend_from_slice(&x_bytes);
            encoded
        } else {
            let mut encoded = Vec::with_capacity(length * 2 + 1);
            encoded.push(0x04);
            encoded.extend_from_slice(&x_bytes);
            encoded.extend_from_slice(&fixed_be(&y.to_integer::<B>(), length));
            encoded
        }
    }

    fn compression_y_tilde(x: &F2mFieldElement<P>, y: &F2mFieldElement<P>) -> bool {
        !x.is_zero() && (y / x).test_bit_zero()
    }

    /// 點倍乘二。
    pub fn twice(&self) -> Self {
        let Some((x, y)) = &self.coords else {
            return self.clone();
        };
        if x.is_zero() {
            return Self::infinity(Arc::clone(&self.curve));
        }
        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => self.twice_affine(x, y),
            _ => unreachable!("tc_f2m_curve currently constructs affine points only"),
        }
    }

    fn twice_affine(&self, x: &F2mFieldElement<P>, y: &F2mFieldElement<P>) -> Self {
        let lambda = &(y / x) + x;
        let x3 = &(&lambda.square() + &lambda) + self.curve.a();
        let y3 = x.square_plus_product(&x3, &lambda.add_one());
        Self::new(Arc::clone(&self.curve), x3, y3)
    }

    fn add_affine(
        &self,
        x1: &F2mFieldElement<P>,
        y1: &F2mFieldElement<P>,
        x2: &F2mFieldElement<P>,
        y2: &F2mFieldElement<P>,
    ) -> Self {
        let dx = x1 + x2;
        let dy = y1 + y2;
        if dx.is_zero() {
            return if dy.is_zero() {
                self.twice()
            } else {
                Self::infinity(Arc::clone(&self.curve))
            };
        }
        let lambda = &dy / &dx;
        let x3 = &(&(&lambda.square() + &lambda) + &dx) + self.curve.a();
        let y3 = &(&(&lambda * &(x1 + &x3)) + &x3) + y1;
        Self::new(Arc::clone(&self.curve), x3, y3)
    }

    /// 由最高位到最低位執行 double-and-add。
    pub fn mul_double_and_add(&self, scalar: &B) -> Self {
        if self.is_infinity() || scalar.bit_length() == 0 {
            return Self::infinity(Arc::clone(&self.curve));
        }
        let mut result = Self::infinity(Arc::clone(&self.curve));
        let mut bit = scalar.bit_length();
        while bit > 0 {
            bit -= 1;
            result = result.twice();
            if scalar.test_bit(bit) {
                result = &result + self;
            }
        }
        result
    }
}

fn fixed_be<B: F2mInteger>(value: &B, length: usize) -> Vec<u8> {
    let mut encoded = alloc::vec![0_u8; length];
    let value_length = value.byte_length_unsigned();
    assert!(value_length <= length, "coordinate exceeds the field width");
    value
        .write_unsigned_be_bytes(&mut encoded[length - value_length..])
        .expect("coordinate output has the exact magnitude width");
    encoded
}

impl<P: BinaryPolyOps, B: F2mInteger> PartialEq for F2mPoint<P, B> {
    fn eq(&self, other: &Self) -> bool {
        (Arc::ptr_eq(&self.curve, &other.curve) || self.curve == other.curve)
            && self.coords == other.coords
    }
}

impl<P: BinaryPolyOps, B: F2mInteger> Eq for F2mPoint<P, B> {}

impl<P: BinaryPolyOps, B: F2mInteger> core::fmt::Debug for F2mPoint<P, B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.coords {
            None => f.write_str("F2mPoint(infinity)"),
            Some((x, y)) => f
                .debug_tuple("F2mPoint")
                .field(&x.value().as_limbs())
                .field(&y.value().as_limbs())
                .finish(),
        }
    }
}

impl<P: F2mPolynomial, B: F2mInteger> Add for &F2mPoint<P, B> {
    type Output = F2mPoint<P, B>;

    fn add(self, rhs: Self) -> Self::Output {
        debug_assert!(Arc::ptr_eq(&self.curve, &rhs.curve) || self.curve == rhs.curve);
        let Some((x1, y1)) = &self.coords else {
            return rhs.clone();
        };
        let Some((x2, y2)) = &rhs.coords else {
            return self.clone();
        };
        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => self.add_affine(x1, y1, x2, y2),
            _ => unreachable!("tc_f2m_curve currently constructs affine points only"),
        }
    }
}

impl<P: F2mPolynomial, B: F2mInteger> Sub for &F2mPoint<P, B> {
    type Output = F2mPoint<P, B>;

    fn sub(self, rhs: Self) -> Self::Output {
        if rhs.is_infinity() {
            self.clone()
        } else {
            self + &(-rhs)
        }
    }
}

impl<P: F2mPolynomial, B: F2mInteger> Neg for &F2mPoint<P, B> {
    type Output = F2mPoint<P, B>;

    fn neg(self) -> Self::Output {
        let Some((x, y)) = &self.coords else {
            return self.clone();
        };
        if x.is_zero() {
            return self.clone();
        }
        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => {
                Self::Output::new(Arc::clone(&self.curve), x.clone(), y + x)
            }
            _ => unreachable!("tc_f2m_curve currently constructs affine points only"),
        }
    }
}

impl<P: F2mPolynomial, B: F2mInteger> Mul<&B> for &F2mPoint<P, B> {
    type Output = F2mPoint<P, B>;

    fn mul(self, rhs: &B) -> Self::Output {
        self.mul_double_and_add(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::named_curves::sect163k1_with;
    use tc_bigint::{BigUint, U256};
    use tc_binpoly::FixedBinaryPoly;

    fn exercise<P: F2mPolynomial, B: F2mInteger>() {
        let (_, point) = sect163k1_with::<P, B>();
        assert!(point.is_valid());
        assert_eq!(&point + &point, point.twice());
        assert!((&point + &(-&point)).is_infinity());
    }

    #[test]
    fn affine_formulas_run_on_both_polynomial_backends() {
        exercise::<BinaryPoly, BigUint>();
        exercise::<FixedBinaryPoly<3>, U256>();
    }
}
