//! 質數曲線上的 affine 與投影座標點。
//!
//! 公式依 Bouncy Castle `FpPoint` 的座標分支移植。座標使用 enum 保存，避免
//! `Z` 陣列長度錯誤或 modified Jacobian 遺漏 `aZ^4` 等非法狀態。

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Add, Mul, Neg, Sub};

use tc_bigint::BigUint;

use crate::{CoordinateSystem, FpCurve, FpFieldElement, FpInteger, PointEncodeError};

#[derive(Clone)]
enum Coords<F> {
    Affine { x: F, y: F },
    Homogeneous { x: F, y: F, z: F },
    Jacobian { x: F, y: F, z: F },
    JacobianModified { x: F, y: F, z: F, az4: Option<F> },
}

struct EqualityParts<'a, B: FpInteger> {
    x: &'a FpFieldElement<B>,
    y: &'a FpFieldElement<B>,
    z: Option<&'a FpFieldElement<B>>,
    x_power: usize,
    y_power: usize,
}

impl<F> Coords<F> {
    const fn coordinate_system(&self) -> CoordinateSystem {
        match self {
            Self::Affine { .. } => CoordinateSystem::Affine,
            Self::Homogeneous { .. } => CoordinateSystem::Homogeneous,
            Self::Jacobian { .. } => CoordinateSystem::Jacobian,
            Self::JacobianModified { .. } => CoordinateSystem::JacobianModified,
        }
    }

    fn x(&self) -> &F {
        match self {
            Self::Affine { x, .. }
            | Self::Homogeneous { x, .. }
            | Self::Jacobian { x, .. }
            | Self::JacobianModified { x, .. } => x,
        }
    }

    fn y(&self) -> &F {
        match self {
            Self::Affine { y, .. }
            | Self::Homogeneous { y, .. }
            | Self::Jacobian { y, .. }
            | Self::JacobianModified { y, .. } => y,
        }
    }

    fn z(&self) -> Option<&F> {
        match self {
            Self::Affine { .. } => None,
            Self::Homogeneous { z, .. }
            | Self::Jacobian { z, .. }
            | Self::JacobianModified { z, .. } => Some(z),
        }
    }
}

/// [`FpCurve`] 上的一個點；`coords == None` 表示群單位元。
#[derive(Clone)]
pub struct FpPoint<B: FpInteger = BigUint> {
    curve: Arc<FpCurve<B>>,
    coords: Option<Coords<FpFieldElement<B>>>,
}

impl<B: FpInteger> FpPoint<B> {
    /// 以 affine 座標建立點，並轉成曲線選定的內部座標系。
    pub fn new(curve: Arc<FpCurve<B>>, x: FpFieldElement<B>, y: FpFieldElement<B>) -> Self {
        let one = x.one();
        let coords = match curve.coordinate_system() {
            CoordinateSystem::Affine => Coords::Affine { x, y },
            CoordinateSystem::Homogeneous => Coords::Homogeneous { x, y, z: one },
            CoordinateSystem::Jacobian => Coords::Jacobian { x, y, z: one },
            CoordinateSystem::JacobianModified => Coords::JacobianModified {
                x,
                y,
                z: one,
                az4: Some(curve.a().clone()),
            },
            _ => unreachable!("FpCurve rejects unsupported coordinate systems"),
        };
        Self::from_coords(curve, coords)
    }

    fn from_coords(curve: Arc<FpCurve<B>>, coords: Coords<FpFieldElement<B>>) -> Self {
        debug_assert_eq!(coords.coordinate_system(), curve.coordinate_system());
        Self {
            curve,
            coords: Some(coords),
        }
    }

    /// 建立本曲線的無窮遠點。
    pub fn infinity(curve: Arc<FpCurve<B>>) -> Self {
        Self {
            curve,
            coords: None,
        }
    }

    /// 回傳所屬曲線。
    pub fn curve(&self) -> &Arc<FpCurve<B>> {
        &self.curve
    }

    /// 是否為無窮遠點。
    pub fn is_infinity(&self) -> bool {
        self.coords.is_none()
    }

    fn raw_x(&self) -> Option<&FpFieldElement<B>> {
        self.coords.as_ref().map(Coords::x)
    }

    fn raw_y(&self) -> Option<&FpFieldElement<B>> {
        self.coords.as_ref().map(Coords::y)
    }

    /// 回傳正規化後的 affine X 座標；無窮遠點回傳 `None`。
    pub fn x(&self) -> Option<FpFieldElement<B>> {
        let normalized = self.normalize();
        normalized.raw_x().cloned()
    }

    /// 回傳正規化後的 affine Y 座標；無窮遠點回傳 `None`。
    pub fn y(&self) -> Option<FpFieldElement<B>> {
        let normalized = self.normalize();
        normalized.raw_y().cloned()
    }

    /// 取得投影 Z 座標；modified Jacobian 的 index 1 是快取的 `aZ^4`。
    pub fn get_z_coord(&self, index: usize) -> Option<&FpFieldElement<B>> {
        match (self.coords.as_ref()?, index) {
            (Coords::Homogeneous { z, .. } | Coords::Jacobian { z, .. }, 0) => Some(z),
            (Coords::JacobianModified { z, .. }, 0) => Some(z),
            (Coords::JacobianModified { az4, .. }, 1) => az4.as_ref(),
            _ => None,
        }
    }

    /// Affine 點、單位點或 `Z == 1` 的投影點皆已正規化。
    pub fn is_normalized(&self) -> bool {
        self.coords
            .as_ref()
            .is_none_or(|coords| coords.z().is_none_or(FpFieldElement::is_one))
    }

    /// 以一次反元素把投影座標縮放為 `Z == 1`。
    pub fn normalize(&self) -> Self {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        let Some(z) = coords.z() else {
            return self.clone();
        };
        if z.is_one() {
            return self.clone();
        }

        let z_inv = z.invert().expect("finite projective point has non-zero Z");
        let (x, y) = match coords {
            Coords::Homogeneous { x, y, .. } => (x * &z_inv, y * &z_inv),
            Coords::Jacobian { x, y, .. } | Coords::JacobianModified { x, y, .. } => {
                let z_inv2 = z_inv.square();
                let z_inv3 = &z_inv2 * &z_inv;
                (x * &z_inv2, y * &z_inv3)
            }
            Coords::Affine { .. } => unreachable!(),
        };
        Self::new(Arc::clone(&self.curve), x, y)
    }

    /// 驗證曲線方程式；若 `h != 1` 且已知群階，另檢查 `nP = O`。
    pub fn is_valid(&self) -> bool {
        self.satisfies_curve_equation() && self.satisfies_order()
    }

    fn satisfies_curve_equation(&self) -> bool {
        let Some(coords) = &self.coords else {
            return true;
        };
        let x = coords.x();
        let y = coords.y();
        let mut lhs = y.square();
        let mut a = self.curve.a().clone();
        let mut b = self.curve.b().clone();

        match coords {
            Coords::Affine { .. } => {}
            Coords::Homogeneous { z, .. } if !z.is_one() => {
                let z2 = z.square();
                let z3 = z * &z2;
                lhs = &lhs * z;
                a = &a * &z2;
                b = &b * &z3;
            }
            Coords::Jacobian { z, .. } | Coords::JacobianModified { z, .. } if !z.is_one() => {
                let z2 = z.square();
                let z4 = z2.square();
                let z6 = &z2 * &z4;
                a = &a * &z4;
                b = &b * &z6;
            }
            _ => {}
        }

        lhs == &(&(&x.square() + &a) * x) + &b
    }

    fn satisfies_order(&self) -> bool {
        if self.is_infinity() {
            return true;
        }
        let one = B::from_u8(1).expect("Fp integer represents one");
        if self.curve.cofactor().is_some_and(|h| h == &one) {
            return true;
        }
        self.curve
            .order()
            .is_none_or(|n| self.mul_double_and_add(n).is_infinity())
    }

    /// 回傳 `2P`。
    pub fn twice(&self) -> Self {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        if coords.y().is_zero() {
            return Self::infinity(Arc::clone(&self.curve));
        }
        match coords {
            Coords::Affine { x, y } => self.twice_affine(x, y),
            Coords::Homogeneous { x, y, z } => self.twice_homogeneous(x, y, z),
            Coords::Jacobian { x, y, z } => self.twice_jacobian(x, y, z),
            Coords::JacobianModified { .. } => self.twice_jacobian_modified(true),
        }
    }

    fn twice_affine(&self, x: &FpFieldElement<B>, y: &FpFieldElement<B>) -> Self {
        let numerator = &three(&x.square()) + self.curve.a();
        let gamma = &numerator / &two(y);
        let x3 = &gamma.square() - &two(x);
        let y3 = &(&gamma * &(x - &x3)) - y;
        Self::new(Arc::clone(&self.curve), x3, y3)
    }

    fn twice_homogeneous(
        &self,
        x: &FpFieldElement<B>,
        y: &FpFieldElement<B>,
        z: &FpFieldElement<B>,
    ) -> Self {
        let z_is_one = z.is_one();
        let mut w = self.curve.a().clone();
        if !w.is_zero() && !z_is_one {
            w = &w * &z.square();
        }
        w = &w + &three(&x.square());

        let s = if z_is_one { y.clone() } else { y * z };
        let t = if z_is_one { y.square() } else { &s * y };
        let b = x * &t;
        let four_b = four(&b);
        let h = &w.square() - &two(&four_b);
        let two_s = two(&s);
        let x3 = &h * &two_s;
        let two_t = two(&t);
        let y3 = &(&(&four_b - &h) * &w) - &two(&two_t.square());
        let four_s_squared = if z_is_one {
            two(&two_t)
        } else {
            two_s.square()
        };
        let z3 = &two(&four_s_squared) * &s;
        self.point_from_homogeneous(x3, y3, z3)
    }

    fn twice_jacobian(
        &self,
        x: &FpFieldElement<B>,
        y: &FpFieldElement<B>,
        z: &FpFieldElement<B>,
    ) -> Self {
        let z_is_one = z.is_one();
        let y_squared = y.square();
        let t = y_squared.square();
        let a = self.curve.a();
        let a_is_minus_three = -a == three(&a.one());

        let (m, s) = if a_is_minus_three {
            let z_squared = if z_is_one { z.clone() } else { z.square() };
            let product = &(x + &z_squared) * &(x - &z_squared);
            (three(&product), four(&(&y_squared * x)))
        } else {
            let mut m = three(&x.square());
            if z_is_one {
                m = &m + a;
            } else if !a.is_zero() {
                m = &m + &(&z.square().square() * a);
            }
            (m, four(&(x * &y_squared)))
        };

        let x3 = &m.square() - &two(&s);
        let y3 = &(&(&s - &x3) * &m) - &eight(&t);
        let mut z3 = two(y);
        if !z_is_one {
            z3 = &z3 * z;
        }
        self.point_from_jacobian(x3, y3, z3, None)
    }

    fn twice_jacobian_modified(&self, calculate_w: bool) -> Self {
        let Coords::JacobianModified { x, y, z, .. } = self.coords.as_ref().expect("finite point")
        else {
            unreachable!()
        };
        let az4 = self.jacobian_modified_w();
        let m = &three(&x.square()) + &az4;
        let two_y = two(y);
        let two_y_squared = &two_y * y;
        let s = two(&(x * &two_y_squared));
        let x3 = &m.square() - &two(&s);
        let four_t = two_y_squared.square();
        let eight_t = two(&four_t);
        let y3 = &(&m * &(&s - &x3)) - &eight_t;
        let az4_3 = calculate_w.then(|| two(&(&eight_t * &az4)));
        let z3 = if z.is_one() { two_y } else { &two_y * z };
        self.point_from_jacobian_modified(x3, y3, z3, az4_3)
    }

    /// 計算 `2P + Q`，未特化座標依 BC 退回 `twice().add(Q)`。
    pub fn twice_plus(&self, rhs: &Self) -> Self {
        self.assert_same_curve_configuration(rhs);
        if self == rhs {
            return self.three_times();
        }
        if self.is_infinity() {
            return rhs.clone();
        }
        if rhs.is_infinity() {
            return self.twice();
        }
        if self.raw_y().expect("finite point").is_zero() {
            return rhs.clone();
        }

        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => self.twice_plus_affine(rhs),
            CoordinateSystem::JacobianModified => {
                self.twice_jacobian_modified(false).add_point(rhs)
            }
            CoordinateSystem::Homogeneous | CoordinateSystem::Jacobian => {
                self.twice().add_point(rhs)
            }
            _ => unreachable!(),
        }
    }

    fn twice_plus_affine(&self, rhs: &Self) -> Self {
        let x1 = self.raw_x().expect("finite point");
        let y1 = self.raw_y().expect("finite point");
        let x2 = rhs.raw_x().expect("finite point");
        let y2 = rhs.raw_y().expect("finite point");
        let dx = x2 - x1;
        let dy = y2 - y1;
        if dx.is_zero() {
            return if dy.is_zero() {
                self.three_times()
            } else {
                self.clone()
            };
        }

        let x = dx.square();
        let y = dy.square();
        let d = &(&x * &(&two(x1) + x2)) - &y;
        if d.is_zero() {
            return Self::infinity(Arc::clone(&self.curve));
        }
        let d_product = &d * &dx;
        let inverse = d_product.invert().expect("non-zero affine denominator");
        let l1 = &(&d * &inverse) * &dy;
        let l2 = &(&(&(&two(y1) * &x) * &dx) * &inverse) - &l1;
        let x4 = &(&(&l2 - &l1) * &(&l1 + &l2)) + x2;
        let y4 = &(&l2 * &(x1 - &x4)) - y1;
        Self::new(Arc::clone(&self.curve), x4, y4)
    }

    /// 計算 `3P`，未特化座標依 BC 退回 `twice().add(self)`。
    pub fn three_times(&self) -> Self {
        if self.is_infinity() || self.raw_y().expect("finite point").is_zero() {
            return self.clone();
        }
        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => self.three_times_affine(),
            CoordinateSystem::JacobianModified => {
                self.twice_jacobian_modified(false).add_point(self)
            }
            CoordinateSystem::Homogeneous | CoordinateSystem::Jacobian => {
                self.twice().add_point(self)
            }
            _ => unreachable!(),
        }
    }

    fn three_times_affine(&self) -> Self {
        let x1 = self.raw_x().expect("finite point");
        let y1 = self.raw_y().expect("finite point");
        let two_y = two(y1);
        let x = two_y.square();
        let z = &three(&x1.square()) + self.curve.a();
        let y = z.square();
        let d = &(&three(x1) * &x) - &y;
        if d.is_zero() {
            return Self::infinity(Arc::clone(&self.curve));
        }
        let d_product = &d * &two_y;
        let inverse = d_product.invert().expect("non-zero affine denominator");
        let l1 = &(&d * &inverse) * &z;
        let l2 = &(&x.square() * &inverse) - &l1;
        let x4 = &(&(&l2 - &l1) * &(&l1 + &l2)) + x1;
        let y4 = &(&l2 * &(x1 - &x4)) - y1;
        Self::new(Arc::clone(&self.curve), x4, y4)
    }

    /// 計算 `P * 2^exponent`，使用 BC 共用的 modified-Jacobian 迴圈。
    pub fn times_pow2(&self, exponent: usize) -> Self {
        if exponent == 0 || self.is_infinity() {
            return self.clone();
        }
        if exponent == 1 {
            return self.twice();
        }
        if self.raw_y().expect("finite point").is_zero() {
            return Self::infinity(Arc::clone(&self.curve));
        }

        let coordinate_system = self.curve.coordinate_system();
        let mut x = self.raw_x().expect("finite point").clone();
        let mut y = self.raw_y().expect("finite point").clone();
        let mut z = self.get_z_coord(0).cloned().unwrap_or_else(|| x.one());
        let mut w = self.curve.a().clone();

        if !z.is_one() {
            match coordinate_system {
                CoordinateSystem::Homogeneous => {
                    let z_squared = z.square();
                    x = &x * &z;
                    y = &y * &z_squared;
                    w = self.calculate_jacobian_modified_w(&z, Some(&z_squared));
                }
                CoordinateSystem::Jacobian => {
                    w = self.calculate_jacobian_modified_w(&z, None);
                }
                CoordinateSystem::JacobianModified => {
                    w = self.jacobian_modified_w();
                }
                CoordinateSystem::Affine => unreachable!("affine Z is one"),
                _ => unreachable!(),
            }
        }

        for _ in 0..exponent {
            if y.is_zero() {
                return Self::infinity(Arc::clone(&self.curve));
            }
            let x_squared = x.square();
            let mut m = three(&x_squared);
            let two_y = two(&y);
            let two_y_squared = &two_y * &y;
            let s = two(&(&x * &two_y_squared));
            let four_t = two_y_squared.square();
            let eight_t = two(&four_t);
            if !w.is_zero() {
                m = &m + &w;
                w = two(&(&eight_t * &w));
            }
            x = &m.square() - &two(&s);
            y = &(&m * &(&s - &x)) - &eight_t;
            z = if z.is_one() { two_y } else { &two_y * &z };
        }

        match coordinate_system {
            CoordinateSystem::Affine => {
                let z_inv = z.invert().expect("finite doubled point has non-zero Z");
                let z_inv2 = z_inv.square();
                let z_inv3 = &z_inv2 * &z_inv;
                Self::new(Arc::clone(&self.curve), &x * &z_inv2, &y * &z_inv3)
            }
            CoordinateSystem::Homogeneous => {
                x = &x * &z;
                z = &z * &z.square();
                self.point_from_homogeneous(x, y, z)
            }
            CoordinateSystem::Jacobian => self.point_from_jacobian(x, y, z, None),
            CoordinateSystem::JacobianModified => {
                self.point_from_jacobian_modified(x, y, z, Some(w))
            }
            _ => unreachable!(),
        }
    }

    /// 以由最高位到最低位的 double-and-add 計算 `kP`。
    pub fn mul_double_and_add(&self, scalar: &B) -> Self {
        if self.is_infinity() || scalar.is_zero() {
            return Self::infinity(Arc::clone(&self.curve));
        }
        let mut result = Self::infinity(Arc::clone(&self.curve));
        let mut bit = scalar.bit_length();
        while bit > 0 {
            bit -= 1;
            result = result.twice();
            if scalar.test_bit(bit) {
                result = result.add_point(self);
            }
        }
        result
    }

    /// 回傳 X9.62／SEC 1 編碼所需的精確位元組數。
    pub fn encoded_length(&self, compressed: bool) -> usize {
        if self.is_infinity() {
            1
        } else {
            self.curve.affine_point_encoding_length(compressed)
        }
    }

    /// 將 X9.62／SEC 1 編碼寫入呼叫端提供的緩衝。
    ///
    /// 投影點在寫入前只正規化一次；緩衝不足時不會寫入任何位元組。
    pub fn encode_to(
        &self,
        compressed: bool,
        output: &mut [u8],
    ) -> Result<usize, PointEncodeError> {
        let required = self.encoded_length(compressed);
        if output.len() < required {
            return Err(PointEncodeError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        let output = &mut output[..required];
        if self.is_infinity() {
            output[0] = 0;
            return Ok(1);
        }

        let normalized = self.normalize();
        let x = normalized.raw_x().expect("finite point has X");
        let y = normalized.raw_y().expect("finite point has Y");
        let len = self.curve.field_element_encoding_length();
        if compressed {
            output[0] = if y.to_big_uint().test_bit(0) {
                0x03
            } else {
                0x02
            };
            write_field_element(x, &mut output[1..1 + len]);
        } else {
            output[0] = 0x04;
            write_field_element(x, &mut output[1..1 + len]);
            write_field_element(y, &mut output[1 + len..1 + 2 * len]);
        }
        Ok(required)
    }

    /// 配置並回傳 X9.62／SEC 1 編碼。
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let mut output = alloc::vec![0; self.encoded_length(compressed)];
        self.encode_to(compressed, &mut output)
            .expect("freshly allocated point encoding buffer has the exact length");
        output
    }

    fn add_point(&self, rhs: &Self) -> Self {
        self.assert_same_curve_configuration(rhs);
        if self.is_infinity() {
            return rhs.clone();
        }
        if rhs.is_infinity() {
            return self.clone();
        }
        match self.curve.coordinate_system() {
            CoordinateSystem::Affine => self.add_affine(rhs),
            CoordinateSystem::Homogeneous => self.add_homogeneous(rhs),
            CoordinateSystem::Jacobian | CoordinateSystem::JacobianModified => {
                self.add_jacobian(rhs)
            }
            _ => unreachable!(),
        }
    }

    fn assert_same_curve_configuration(&self, rhs: &Self) {
        assert!(
            (Arc::ptr_eq(&self.curve, &rhs.curve) || self.curve == rhs.curve)
                && self.curve.coordinate_system() == rhs.curve.coordinate_system(),
            "cannot add points from different curve configurations"
        );
    }

    fn add_affine(&self, rhs: &Self) -> Self {
        let x1 = self.raw_x().expect("finite point");
        let y1 = self.raw_y().expect("finite point");
        let x2 = rhs.raw_x().expect("finite point");
        let y2 = rhs.raw_y().expect("finite point");
        let dx = x2 - x1;
        let dy = y2 - y1;
        if dx.is_zero() {
            return if dy.is_zero() {
                self.twice()
            } else {
                Self::infinity(Arc::clone(&self.curve))
            };
        }
        let gamma = &dy / &dx;
        let x3 = &(&gamma.square() - x1) - x2;
        let y3 = &(&gamma * &(x1 - &x3)) - y1;
        Self::new(Arc::clone(&self.curve), x3, y3)
    }

    fn add_homogeneous(&self, rhs: &Self) -> Self {
        let (
            Coords::Homogeneous {
                x: x1,
                y: y1,
                z: z1,
            },
            Coords::Homogeneous {
                x: x2,
                y: y2,
                z: z2,
            },
        ) = (
            self.coords.as_ref().expect("finite point"),
            rhs.coords.as_ref().expect("finite point"),
        )
        else {
            unreachable!()
        };
        let z1_is_one = z1.is_one();
        let z2_is_one = z2.is_one();
        let u1 = if z1_is_one { y2.clone() } else { y2 * z1 };
        let u2 = if z2_is_one { y1.clone() } else { y1 * z2 };
        let u = &u1 - &u2;
        let v1 = if z1_is_one { x2.clone() } else { x2 * z1 };
        let v2 = if z2_is_one { x1.clone() } else { x1 * z2 };
        let v = &v1 - &v2;
        if v.is_zero() {
            return if u.is_zero() {
                self.twice()
            } else {
                Self::infinity(Arc::clone(&self.curve))
            };
        }
        let w = if z1_is_one {
            z2.clone()
        } else if z2_is_one {
            z1.clone()
        } else {
            z1 * z2
        };
        let v_squared = v.square();
        let v_cubed = &v_squared * &v;
        let v_squared_v2 = &v_squared * &v2;
        let a = &(&(&u.square() * &w) - &v_cubed) - &two(&v_squared_v2);
        let x3 = &v * &a;
        let y3 = multiply_minus_product(&(&v_squared_v2 - &a), &u, &u2, &v_cubed);
        let z3 = &v_cubed * &w;
        self.point_from_homogeneous(x3, y3, z3)
    }

    fn add_jacobian(&self, rhs: &Self) -> Self {
        let x1 = self.raw_x().expect("finite point");
        let y1 = self.raw_y().expect("finite point");
        let z1 = self.get_z_coord(0).expect("Jacobian point has Z");
        let x2 = rhs.raw_x().expect("finite point");
        let y2 = rhs.raw_y().expect("finite point");
        let z2 = rhs.get_z_coord(0).expect("Jacobian point has Z");
        let z1_is_one = z1.is_one();

        let (x3, y3, z3, z3_squared) = if !z1_is_one && z1 == z2 {
            let dx = x1 - x2;
            let dy = y1 - y2;
            if dx.is_zero() {
                return if dy.is_zero() {
                    self.twice()
                } else {
                    Self::infinity(Arc::clone(&self.curve))
                };
            }
            let c = dx.square();
            let w1 = x1 * &c;
            let w2 = x2 * &c;
            let a1 = &(&w1 - &w2) * y1;
            let x3 = &(&dy.square() - &w1) - &w2;
            let y3 = &(&(&w1 - &x3) * &dy) - &a1;
            let z3 = &dx * z1;
            (x3, y3, z3, None)
        } else {
            let (u2, s2) = if z1_is_one {
                (x2.clone(), y2.clone())
            } else {
                let z1_squared = z1.square();
                let z1_cubed = &z1_squared * z1;
                (&z1_squared * x2, &z1_cubed * y2)
            };
            let z2_is_one = z2.is_one();
            let (u1, s1) = if z2_is_one {
                (x1.clone(), y1.clone())
            } else {
                let z2_squared = z2.square();
                let z2_cubed = &z2_squared * z2;
                (&z2_squared * x1, &z2_cubed * y1)
            };
            let h = &u1 - &u2;
            let r = &s1 - &s2;
            if h.is_zero() {
                return if r.is_zero() {
                    self.twice()
                } else {
                    Self::infinity(Arc::clone(&self.curve))
                };
            }
            let h_squared = h.square();
            let g = &h_squared * &h;
            let v = &h_squared * &u1;
            let x3 = &(&r.square() + &g) - &two(&v);
            let y3 = multiply_minus_product(&(&v - &x3), &r, &g, &s1);
            let mut z3 = h.clone();
            if !z1_is_one {
                z3 = &z3 * z1;
            }
            if !z2_is_one {
                z3 = &z3 * z2;
            }
            let z3_squared = (z1_is_one && z2_is_one).then_some(h_squared);
            (x3, y3, z3, z3_squared)
        };
        self.point_from_jacobian(x3, y3, z3, z3_squared.as_ref())
    }

    fn point_from_homogeneous(
        &self,
        x: FpFieldElement<B>,
        y: FpFieldElement<B>,
        z: FpFieldElement<B>,
    ) -> Self {
        Self::from_coords(Arc::clone(&self.curve), Coords::Homogeneous { x, y, z })
    }

    fn point_from_jacobian(
        &self,
        x: FpFieldElement<B>,
        y: FpFieldElement<B>,
        z: FpFieldElement<B>,
        z_squared: Option<&FpFieldElement<B>>,
    ) -> Self {
        match self.curve.coordinate_system() {
            CoordinateSystem::Jacobian => {
                Self::from_coords(Arc::clone(&self.curve), Coords::Jacobian { x, y, z })
            }
            CoordinateSystem::JacobianModified => {
                let az4 = self.calculate_jacobian_modified_w(&z, z_squared);
                self.point_from_jacobian_modified(x, y, z, Some(az4))
            }
            _ => unreachable!(),
        }
    }

    fn point_from_jacobian_modified(
        &self,
        x: FpFieldElement<B>,
        y: FpFieldElement<B>,
        z: FpFieldElement<B>,
        az4: Option<FpFieldElement<B>>,
    ) -> Self {
        Self::from_coords(
            Arc::clone(&self.curve),
            Coords::JacobianModified { x, y, z, az4 },
        )
    }

    fn calculate_jacobian_modified_w(
        &self,
        z: &FpFieldElement<B>,
        z_squared: Option<&FpFieldElement<B>>,
    ) -> FpFieldElement<B> {
        let a = self.curve.a();
        if a.is_zero() || z.is_one() {
            return a.clone();
        }
        let z_squared = z_squared.cloned().unwrap_or_else(|| z.square());
        a * &z_squared.square()
    }

    fn jacobian_modified_w(&self) -> FpFieldElement<B> {
        let Coords::JacobianModified { z, az4, .. } = self.coords.as_ref().expect("finite point")
        else {
            unreachable!()
        };
        az4.clone()
            .unwrap_or_else(|| self.calculate_jacobian_modified_w(z, None))
    }

    fn equality_parts(&self) -> Option<EqualityParts<'_, B>> {
        let coords = self.coords.as_ref()?;
        let powers = match coords {
            Coords::Affine { .. } => (0, 0),
            Coords::Homogeneous { .. } => (1, 1),
            Coords::Jacobian { .. } | Coords::JacobianModified { .. } => (2, 3),
        };
        Some(EqualityParts {
            x: coords.x(),
            y: coords.y(),
            z: coords.z(),
            x_power: powers.0,
            y_power: powers.1,
        })
    }
}

fn write_field_element<B: FpInteger>(value: &FpFieldElement<B>, output: &mut [u8]) {
    output.fill(0);
    let integer = value.to_big_uint();
    let significant = integer.byte_length_unsigned();
    debug_assert!(significant <= output.len());
    if significant != 0 {
        let start = output.len() - significant;
        integer
            .write_unsigned_be_bytes(&mut output[start..])
            .expect("field element magnitude fits its fixed encoding width");
    }
}

fn two<B: FpInteger>(value: &FpFieldElement<B>) -> FpFieldElement<B> {
    value + value
}

fn three<B: FpInteger>(value: &FpFieldElement<B>) -> FpFieldElement<B> {
    &two(value) + value
}

fn four<B: FpInteger>(value: &FpFieldElement<B>) -> FpFieldElement<B> {
    two(&two(value))
}

fn eight<B: FpInteger>(value: &FpFieldElement<B>) -> FpFieldElement<B> {
    four(&two(value))
}

fn multiply_minus_product<B: FpInteger>(
    left: &FpFieldElement<B>,
    right: &FpFieldElement<B>,
    other_left: &FpFieldElement<B>,
    other_right: &FpFieldElement<B>,
) -> FpFieldElement<B> {
    &(left * right) - &(other_left * other_right)
}

fn scale_by_z<B: FpInteger>(
    value: &FpFieldElement<B>,
    z: Option<&FpFieldElement<B>>,
    power: usize,
) -> FpFieldElement<B> {
    let Some(z) = z else {
        return value.clone();
    };
    if power == 0 || z.is_one() {
        return value.clone();
    }
    let scale = match power {
        1 => z.clone(),
        2 => z.square(),
        3 => &z.square() * z,
        _ => unreachable!(),
    };
    value * &scale
}

impl<B: FpInteger> PartialEq for FpPoint<B> {
    fn eq(&self, other: &Self) -> bool {
        if !(Arc::ptr_eq(&self.curve, &other.curve) || self.curve == other.curve) {
            return false;
        }
        let (Some(left), Some(right)) = (self.equality_parts(), other.equality_parts()) else {
            return self.is_infinity() && other.is_infinity();
        };

        scale_by_z(left.x, right.z, right.x_power) == scale_by_z(right.x, left.z, left.x_power)
            && scale_by_z(left.y, right.z, right.y_power)
                == scale_by_z(right.y, left.z, left.y_power)
    }
}

impl<B: FpInteger> Eq for FpPoint<B> {}

impl<B: FpInteger> core::fmt::Debug for FpPoint<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Some(coords) = &self.coords else {
            return f.write_str("FpPoint(infinity)");
        };
        f.debug_struct("FpPoint")
            .field("coordinate_system", &coords.coordinate_system())
            .field("x", &coords.x().to_big_uint())
            .field("y", &coords.y().to_big_uint())
            .field("z", &coords.z().map(FpFieldElement::to_big_uint))
            .finish()
    }
}

impl<B: FpInteger> Neg for &FpPoint<B> {
    type Output = FpPoint<B>;

    fn neg(self) -> Self::Output {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        let coords = match coords {
            Coords::Affine { x, y } => Coords::Affine {
                x: x.clone(),
                y: -y,
            },
            Coords::Homogeneous { x, y, z } => Coords::Homogeneous {
                x: x.clone(),
                y: -y,
                z: z.clone(),
            },
            Coords::Jacobian { x, y, z } => Coords::Jacobian {
                x: x.clone(),
                y: -y,
                z: z.clone(),
            },
            Coords::JacobianModified { x, y, z, az4 } => Coords::JacobianModified {
                x: x.clone(),
                y: -y,
                z: z.clone(),
                az4: az4.clone(),
            },
        };
        FpPoint::from_coords(Arc::clone(&self.curve), coords)
    }
}

impl<B: FpInteger> Add for &FpPoint<B> {
    type Output = FpPoint<B>;

    fn add(self, rhs: Self) -> Self::Output {
        self.add_point(rhs)
    }
}

impl<B: FpInteger> Sub for &FpPoint<B> {
    type Output = FpPoint<B>;

    fn sub(self, rhs: Self) -> Self::Output {
        self + &(-rhs)
    }
}

impl<B: FpInteger> Mul<&B> for &FpPoint<B> {
    type Output = FpPoint<B>;

    fn mul(self, rhs: &B) -> Self::Output {
        self.mul_double_and_add(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn curve17(coordinate_system: CoordinateSystem) -> Arc<FpCurve> {
        Arc::new(
            FpCurve::new(
                BigUint::from(17_u8),
                BigUint::from(2_u8),
                BigUint::from(2_u8),
                None,
                None,
            )
            .with_coordinate_system(coordinate_system),
        )
    }

    fn point(curve: &Arc<FpCurve>, x: u8, y: u8) -> FpPoint {
        curve.create_point(BigUint::from(x), BigUint::from(y))
    }

    fn coordinate_systems() -> [CoordinateSystem; 4] {
        [
            CoordinateSystem::Affine,
            CoordinateSystem::Homogeneous,
            CoordinateSystem::Jacobian,
            CoordinateSystem::JacobianModified,
        ]
    }

    #[test]
    fn group_operations_match_known_values_in_every_coordinate_system() {
        for coordinate_system in coordinate_systems() {
            let curve = curve17(coordinate_system);
            let g = point(&curve, 5, 1);
            let two_g = g.twice();
            assert_eq!(two_g, point(&curve, 6, 3));
            assert_eq!(&g + &two_g, point(&curve, 10, 6));
            assert_eq!(&g * &BigUint::from(3_u8), point(&curve, 10, 6));
            assert_eq!(g.three_times(), g.twice().add_point(&g));
            assert_eq!(g.twice_plus(&two_g), g.twice().add_point(&two_g));
            assert_eq!(g.times_pow2(3), g.twice().twice().twice());
            assert!((&g + &(-&g)).is_infinity());
        }
    }

    #[test]
    fn identity_handles_every_operation() {
        for coordinate_system in coordinate_systems() {
            let curve = curve17(coordinate_system);
            let point = point(&curve, 5, 1);
            let identity = curve.infinity();
            assert_eq!(&identity + &point, point);
            assert_eq!(&point + &identity, point);
            assert_eq!(identity.twice(), identity);
            assert_eq!(identity.twice_plus(&point), point);
            assert_eq!(point.twice_plus(&identity), point.twice());
            assert_eq!(identity.three_times(), identity);
            assert_eq!(identity.times_pow2(8), identity);
            assert_eq!(-&identity, identity);
        }
    }

    #[test]
    fn projective_equality_uses_cross_products() {
        let lambda_value = BigUint::from(3_u8);
        for coordinate_system in [
            CoordinateSystem::Homogeneous,
            CoordinateSystem::Jacobian,
            CoordinateSystem::JacobianModified,
        ] {
            let curve = curve17(coordinate_system);
            let point = point(&curve, 5, 1);
            let lambda = curve.create_field_element(lambda_value.clone());
            let lambda2 = lambda.square();
            let lambda3 = &lambda2 * &lambda;
            let lambda4 = lambda2.square();
            let x = point.raw_x().unwrap();
            let y = point.raw_y().unwrap();
            let scaled = match coordinate_system {
                CoordinateSystem::Homogeneous => Coords::Homogeneous {
                    x: x * &lambda,
                    y: y * &lambda,
                    z: lambda,
                },
                CoordinateSystem::Jacobian => Coords::Jacobian {
                    x: x * &lambda2,
                    y: y * &lambda3,
                    z: lambda,
                },
                CoordinateSystem::JacobianModified => Coords::JacobianModified {
                    x: x * &lambda2,
                    y: y * &lambda3,
                    z: lambda,
                    az4: Some(point.get_z_coord(1).unwrap() * &lambda4),
                },
                _ => unreachable!(),
            };
            let scaled = FpPoint::from_coords(Arc::clone(&curve), scaled);
            assert!(!scaled.is_normalized());
            assert_eq!(point, scaled);
            assert_eq!(point, scaled.normalize());
        }
    }

    #[test]
    fn modified_jacobian_lazy_w_matches_the_eager_cache() {
        let curve = curve17(CoordinateSystem::JacobianModified);
        let point_value = point(&curve, 5, 1);
        let other = point(&curve, 10, 6);
        let eager = point_value.twice_jacobian_modified(true);
        let lazy = point_value.twice_jacobian_modified(false);

        assert!(matches!(
            &eager.coords,
            Some(Coords::JacobianModified { az4: Some(_), .. })
        ));
        assert!(matches!(
            &lazy.coords,
            Some(Coords::JacobianModified { az4: None, .. })
        ));
        assert_eq!(lazy, eager);
        assert_eq!(lazy.jacobian_modified_w(), eager.jacobian_modified_w());
        assert_eq!(lazy.twice_plus(&other), eager.twice_plus(&other));
        assert_eq!(lazy.three_times(), eager.three_times());
    }

    #[test]
    fn encode_to_matches_allocating_encoding_in_every_coordinate_system() {
        let (base_curve, generator) = crate::named_curves::secp256k1();
        let x = generator.x().unwrap().to_big_uint();
        let y = generator.y().unwrap().to_big_uint();

        for coordinate_system in coordinate_systems() {
            let curve = Arc::new(
                (*base_curve)
                    .clone()
                    .with_coordinate_system(coordinate_system),
            );
            let point = curve.create_point(x, y).times_pow2(3);

            for compressed in [false, true] {
                let expected = point.encode(compressed);
                let required = point.encoded_length(compressed);
                assert_eq!(expected.len(), required);

                let mut output = [0_u8; 65];
                assert_eq!(
                    point.encode_to(compressed, &mut output[..required]),
                    Ok(required)
                );
                assert_eq!(&output[..required], expected);

                let mut short = [0xA5_u8; 64];
                assert_eq!(
                    point.encode_to(compressed, &mut short[..required - 1]),
                    Err(PointEncodeError::OutputTooShort {
                        required,
                        available: required - 1,
                    })
                );
                assert!(short.iter().all(|byte| *byte == 0xA5));
            }

            let infinity = curve.infinity();
            assert_eq!(infinity.encoded_length(false), 1);
            let mut encoded = [0xA5];
            assert_eq!(infinity.encode_to(false, &mut encoded), Ok(1));
            assert_eq!(encoded, [0]);
            assert_eq!(
                infinity.encode_to(true, &mut []),
                Err(PointEncodeError::OutputTooShort {
                    required: 1,
                    available: 0,
                })
            );
        }
    }
}
