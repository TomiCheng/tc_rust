//! 質數曲線上的 affine 點。
//!
//! Step 2 先保留最容易與舊 `tc_ec` 對照的 affine 公式；每次加法或倍點會做
//! 一次體域反元素。表示法故意不帶舊版的帶符號純量與 projective `Z` 座標。

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Add, Mul, Neg, Sub};

use tc_bigint::BigUint;

use crate::{CoordinateSystem, FpCurve, FpFieldElement};

/// [`FpCurve`] 上的一個點；`None` 表示群單位元（無窮遠點）。
#[derive(Clone)]
pub struct FpPoint {
    curve: Arc<FpCurve>,
    coords: Option<(FpFieldElement, FpFieldElement)>,
}

impl FpPoint {
    /// 建立 affine 點；呼叫端可用 [`Self::is_valid`] 驗證曲線方程式。
    pub fn new(curve: Arc<FpCurve>, x: FpFieldElement, y: FpFieldElement) -> Self {
        Self {
            curve,
            coords: Some((x, y)),
        }
    }

    /// 建立本曲線的無窮遠點。
    pub fn infinity(curve: Arc<FpCurve>) -> Self {
        Self {
            curve,
            coords: None,
        }
    }

    /// 回傳所屬曲線。
    pub fn curve(&self) -> &Arc<FpCurve> {
        &self.curve
    }

    /// 是否為無窮遠點。
    pub fn is_infinity(&self) -> bool {
        self.coords.is_none()
    }

    /// 回傳 affine X 座標；無窮遠點回傳 `None`。
    pub fn x(&self) -> Option<&FpFieldElement> {
        self.coords.as_ref().map(|(x, _)| x)
    }

    /// 回傳 affine Y 座標；無窮遠點回傳 `None`。
    pub fn y(&self) -> Option<&FpFieldElement> {
        self.coords.as_ref().map(|(_, y)| y)
    }

    /// Affine 表示已正規化，因此直接複製。
    pub fn normalize(&self) -> Self {
        self.clone()
    }

    /// 驗證曲線方程式；若 `h != 1` 且已知群階，另檢查 `nP = O`。
    pub fn is_valid(&self) -> bool {
        match &self.coords {
            None => true,
            Some((x, y)) => self.curve.contains_affine(x, y) && self.satisfies_order(),
        }
    }

    fn satisfies_order(&self) -> bool {
        if self
            .curve
            .cofactor()
            .is_some_and(|h| h == &BigUint::from(1_u8))
        {
            return true;
        }
        self.curve
            .order()
            .is_none_or(|n| self.mul_double_and_add(n).is_infinity())
    }

    /// 回傳 `2P`。
    pub fn twice(&self) -> Self {
        let Some((x, y)) = &self.coords else {
            return self.clone();
        };
        if y.is_zero() {
            return Self::infinity(Arc::clone(&self.curve));
        }
        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => self.twice_affine(x, y),
            _ => todo!("目前只實作 affine 座標倍點"),
        }
    }

    fn twice_affine(&self, x: &FpFieldElement, y: &FpFieldElement) -> Self {
        let x_squared = x.square();
        let three_x_squared = &(&x_squared + &x_squared) + &x_squared;
        let lambda = &(&three_x_squared + self.curve.a()) / &(y + y);
        let x3 = &lambda.square() - &(x + x);
        let y3 = &(&lambda * &(x - &x3)) - y;
        Self::new(Arc::clone(&self.curve), x3, y3)
    }

    fn add_affine(&self, rhs: &Self) -> Self {
        let (x1, y1) = self.coords.as_ref().expect("left point is finite");
        let (x2, y2) = rhs.coords.as_ref().expect("right point is finite");
        let dx = x2 - x1;
        let dy = y2 - y1;
        if dx.is_zero() {
            return if dy.is_zero() {
                self.twice()
            } else {
                Self::infinity(Arc::clone(&self.curve))
            };
        }
        let lambda = &dy / &dx;
        let x3 = &(&lambda.square() - x1) - x2;
        let y3 = &(&lambda * &(x1 - &x3)) - y1;
        Self::new(Arc::clone(&self.curve), x3, y3)
    }

    /// 以由最高位到最低位的 double-and-add 計算 `kP`。
    pub fn mul_double_and_add(&self, scalar: &BigUint) -> Self {
        if self.is_infinity() || scalar.is_zero() {
            return Self::infinity(Arc::clone(&self.curve));
        }
        let mut result = Self::infinity(Arc::clone(&self.curve));
        let mut bit = scalar.bits();
        while bit > 0 {
            bit -= 1;
            result = result.twice();
            if scalar.test_bit(bit) {
                result = &result + self;
            }
        }
        result
    }

    /// 以 X9.62／SEC 1 格式編碼點。
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let Some((x, y)) = &self.coords else {
            return alloc::vec![0];
        };
        let len = self.curve.field_element_encoding_length();
        let x = fixed_be(&x.to_big_uint(), len);
        if compressed {
            let mut output = Vec::with_capacity(1 + len);
            output.push(if y.to_big_uint().test_bit(0) {
                0x03
            } else {
                0x02
            });
            output.extend_from_slice(&x);
            output
        } else {
            let mut output = Vec::with_capacity(1 + 2 * len);
            output.push(0x04);
            output.extend_from_slice(&x);
            output.extend_from_slice(&fixed_be(&y.to_big_uint(), len));
            output
        }
    }
}

fn fixed_be(value: &BigUint, len: usize) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut output = alloc::vec![0_u8; len];
    let significant = if value.is_zero() { 0 } else { bytes.len() };
    if significant != 0 {
        output[len - significant..].copy_from_slice(&bytes);
    }
    output
}

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
            None => f.write_str("FpPoint(infinity)"),
            Some((x, y)) => f
                .debug_tuple("FpPoint")
                .field(&x.to_big_uint())
                .field(&y.to_big_uint())
                .finish(),
        }
    }
}

impl Neg for &FpPoint {
    type Output = FpPoint;

    fn neg(self) -> Self::Output {
        match &self.coords {
            None => self.clone(),
            Some((x, y)) => FpPoint::new(Arc::clone(&self.curve), x.clone(), -y),
        }
    }
}

impl Add for &FpPoint {
    type Output = FpPoint;

    fn add(self, rhs: Self) -> Self::Output {
        assert_eq!(
            self.curve, rhs.curve,
            "cannot add points from different curves"
        );
        if self.is_infinity() {
            return rhs.clone();
        }
        if rhs.is_infinity() {
            return self.clone();
        }
        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => self.add_affine(rhs),
            _ => todo!("目前只實作 affine 座標加法"),
        }
    }
}

impl Sub for &FpPoint {
    type Output = FpPoint;

    fn sub(self, rhs: Self) -> Self::Output {
        self + &(-rhs)
    }
}

impl Mul<&BigUint> for &FpPoint {
    type Output = FpPoint;

    fn mul(self, rhs: &BigUint) -> Self::Output {
        self.mul_double_and_add(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn curve17() -> Arc<FpCurve> {
        Arc::new(FpCurve::new(
            BigUint::from(17_u8),
            BigUint::from(2_u8),
            BigUint::from(2_u8),
            None,
            None,
        ))
    }

    fn point(curve: &Arc<FpCurve>, x: u8, y: u8) -> FpPoint {
        curve.create_point(BigUint::from(x), BigUint::from(y))
    }

    #[test]
    fn affine_group_operations_match_known_values() {
        let curve = curve17();
        let g = point(&curve, 5, 1);
        let two_g = g.twice();
        assert_eq!(two_g, point(&curve, 6, 3));
        assert_eq!(&g + &two_g, point(&curve, 10, 6));
        assert_eq!(&g * &BigUint::from(3_u8), point(&curve, 10, 6));
        assert!(&g + &(-&g) == curve.infinity());
    }
}
