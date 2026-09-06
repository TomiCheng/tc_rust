//! secp256r1 的 Jacobian 點運算。

use alloc::{sync::Arc, vec, vec::Vec};
use core::ops::{Add, Neg};

use tc_bigint::U256;
use tc_ec_core::{Curve, Point, PointEncodeError, scalar_mul};

use crate::{SecP256R1Curve, SecP256R1FieldElement};

#[derive(Clone)]
struct Jacobian {
    x: SecP256R1FieldElement,
    y: SecP256R1FieldElement,
    z: SecP256R1FieldElement,
}

/// secp256r1 上的 Jacobian 點；`coordinates == None` 表示無窮遠點。
#[derive(Clone)]
pub struct SecP256R1Point {
    curve: Arc<SecP256R1Curve>,
    coordinates: Option<Jacobian>,
}

impl SecP256R1Point {
    /// 由 affine 欄位座標建立 `Z = 1` 的 Jacobian 點。
    pub fn new(
        curve: Arc<SecP256R1Curve>,
        x: SecP256R1FieldElement,
        y: SecP256R1FieldElement,
    ) -> Self {
        Self::from_jacobian(curve, x, y, SecP256R1FieldElement::ONE)
    }

    pub(crate) fn from_jacobian(
        curve: Arc<SecP256R1Curve>,
        x: SecP256R1FieldElement,
        y: SecP256R1FieldElement,
        z: SecP256R1FieldElement,
    ) -> Self {
        Self {
            curve,
            coordinates: Some(Jacobian { x, y, z }),
        }
    }

    /// 建立無窮遠點。
    pub fn infinity(curve: Arc<SecP256R1Curve>) -> Self {
        Self {
            curve,
            coordinates: None,
        }
    }

    /// 回傳所屬曲線。
    pub fn curve(&self) -> &Arc<SecP256R1Curve> {
        &self.curve
    }

    /// 是否為無窮遠點。
    pub fn is_infinity(&self) -> bool {
        self.coordinates.is_none()
    }

    /// 未正規化的 X 座標。
    pub fn raw_x(&self) -> Option<&SecP256R1FieldElement> {
        self.coordinates.as_ref().map(|point| &point.x)
    }

    /// 未正規化的 Y 座標。
    pub fn raw_y(&self) -> Option<&SecP256R1FieldElement> {
        self.coordinates.as_ref().map(|point| &point.y)
    }

    /// Jacobian Z 座標。
    pub fn z(&self) -> Option<&SecP256R1FieldElement> {
        self.coordinates.as_ref().map(|point| &point.z)
    }

    /// 正規化後的 affine X 座標。
    pub fn x(&self) -> Option<SecP256R1FieldElement> {
        self.normalize().raw_x().copied()
    }

    /// 正規化後的 affine Y 座標。
    pub fn y(&self) -> Option<SecP256R1FieldElement> {
        self.normalize().raw_y().copied()
    }

    /// 以一次反元素轉為 `Z = 1`。
    pub fn normalize(&self) -> Self {
        let Some(point) = &self.coordinates else {
            return self.clone();
        };
        if point.z.is_one() {
            return self.clone();
        }
        let z_inverse = point
            .z
            .invert()
            .expect("finite Jacobian point has non-zero Z");
        let z_inverse_squared = z_inverse.square();
        let z_inverse_cubed = &z_inverse_squared * &z_inverse;
        Self::new(
            Arc::clone(&self.curve),
            &point.x * &z_inverse_squared,
            &point.y * &z_inverse_cubed,
        )
    }

    /// 點加法。
    pub fn add_point(&self, rhs: &Self) -> Self {
        self.assert_same_curve(rhs);
        let Some(left) = &self.coordinates else {
            return rhs.clone();
        };
        let Some(right) = &rhs.coordinates else {
            return self.clone();
        };

        let (u1, s1) = scale_affine(&left.x, &left.y, &right.z);
        let (u2, s2) = scale_affine(&right.x, &right.y, &left.z);
        let h = &u2 - &u1;
        let r = &s2 - &s1;
        if h.is_zero() {
            return if r.is_zero() {
                self.twice()
            } else {
                self.curve.infinity()
            };
        }

        let h_squared = h.square();
        let h_cubed = &h_squared * &h;
        let v = &u1 * &h_squared;
        let x3 = &(&r.square() - &h_cubed) - &twice(&v);
        let y3 = &(&r * &(&v - &x3)) - &(&s1 * &h_cubed);
        let mut z3 = h;
        if !left.z.is_one() {
            z3 = &z3 * &left.z;
        }
        if !right.z.is_one() {
            z3 = &z3 * &right.z;
        }
        Self::from_jacobian(Arc::clone(&self.curve), x3, y3, z3)
    }

    /// 點倍乘二，使用 `a = -3` 的 Jacobian 公式。
    pub fn twice(&self) -> Self {
        let Some(point) = &self.coordinates else {
            return self.clone();
        };
        if point.y.is_zero() {
            return self.curve.infinity();
        }

        let y_squared = point.y.square();
        let t = y_squared.square();
        let z_squared = if point.z.is_one() {
            point.z
        } else {
            point.z.square()
        };
        let m = triple(&(&(&point.x + &z_squared) * &(&point.x - &z_squared)));
        let s = quadruple(&(&point.x * &y_squared));
        let x3 = &m.square() - &twice(&s);
        let y3 = &(&m * &(&s - &x3)) - &octuple(&t);
        let mut z3 = twice(&point.y);
        if !point.z.is_one() {
            z3 = &z3 * &point.z;
        }
        Self::from_jacobian(Arc::clone(&self.curve), x3, y3, z3)
    }

    /// `2P + Q`；依 bc 特化點退回倍點後加法。
    pub fn twice_plus(&self, rhs: &Self) -> Self {
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
        self.twice().add_point(rhs)
    }

    /// `3P`；依 bc 特化點退回倍點後加法。
    pub fn three_times(&self) -> Self {
        if self.is_infinity() || self.raw_y().expect("finite point").is_zero() {
            self.clone()
        } else {
            self.twice().add_point(self)
        }
    }

    /// `P * 2^exponent`。
    pub fn times_pow2(&self, exponent: usize) -> Self {
        let mut result = self.clone();
        for _ in 0..exponent {
            result = result.twice();
        }
        result
    }

    /// 點的加法反元素。
    pub fn negate(&self) -> Self {
        let Some(point) = &self.coordinates else {
            return self.clone();
        };
        Self::from_jacobian(Arc::clone(&self.curve), point.x, point.y.negate(), point.z)
    }

    /// 驗證正規化座標是否滿足曲線方程式。
    pub fn is_valid(&self) -> bool {
        let normalized = self.normalize();
        normalized
            .coordinates
            .as_ref()
            .is_none_or(|point| normalized.curve.contains_affine(&point.x, &point.y))
    }

    /// 共用 double-and-add 乘法器的便利入口。
    pub fn mul_double_and_add(&self, scalar: &U256) -> Self {
        scalar_mul::<SecP256R1Curve>(self, scalar)
    }

    /// SEC 1 編碼長度。
    pub fn encoded_length(&self, compressed: bool) -> usize {
        if self.is_infinity() {
            1
        } else if compressed {
            33
        } else {
            65
        }
    }

    /// 寫入 SEC 1 編碼；緩衝不足時不寫入。
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
        if self.is_infinity() {
            output[0] = 0;
            return Ok(1);
        }
        let normalized = self.normalize();
        let point = normalized.coordinates.as_ref().expect("finite point");
        if compressed {
            output[0] = if point.y.test_bit_zero() { 3 } else { 2 };
            point.x.encode_to((&mut output[1..33]).try_into().unwrap());
        } else {
            output[0] = 4;
            point.x.encode_to((&mut output[1..33]).try_into().unwrap());
            point.y.encode_to((&mut output[33..65]).try_into().unwrap());
        }
        Ok(required)
    }

    /// 配置並回傳 SEC 1 編碼。
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let mut output = vec![0_u8; self.encoded_length(compressed)];
        self.encode_to(compressed, &mut output)
            .expect("fresh encoding buffer has exact length");
        output
    }

    fn assert_same_curve(&self, rhs: &Self) {
        assert!(
            Arc::ptr_eq(&self.curve, &rhs.curve) || self.curve == rhs.curve,
            "cannot add points from different curves"
        );
    }
}

fn scale_affine(
    x: &SecP256R1FieldElement,
    y: &SecP256R1FieldElement,
    z: &SecP256R1FieldElement,
) -> (SecP256R1FieldElement, SecP256R1FieldElement) {
    if z.is_one() {
        return (*x, *y);
    }
    let z_squared = z.square();
    let z_cubed = &z_squared * z;
    (&z_squared * x, &z_cubed * y)
}

fn twice(value: &SecP256R1FieldElement) -> SecP256R1FieldElement {
    value + value
}

fn triple(value: &SecP256R1FieldElement) -> SecP256R1FieldElement {
    &twice(value) + value
}

fn quadruple(value: &SecP256R1FieldElement) -> SecP256R1FieldElement {
    twice(&twice(value))
}

fn octuple(value: &SecP256R1FieldElement) -> SecP256R1FieldElement {
    twice(&quadruple(value))
}

impl Point for SecP256R1Point {
    type Curve = SecP256R1Curve;

    fn identity(&self) -> Self {
        self.curve.infinity()
    }

    fn is_identity(&self) -> bool {
        self.is_infinity()
    }

    fn x(&self) -> Option<<Self::Curve as Curve>::Field> {
        self.x()
    }

    fn y(&self) -> Option<<Self::Curve as Curve>::Field> {
        self.y()
    }

    fn add(&self, rhs: &Self) -> Self {
        self.add_point(rhs)
    }

    fn double(&self) -> Self {
        self.twice()
    }

    fn twice_plus(&self, rhs: &Self) -> Self {
        self.twice_plus(rhs)
    }

    fn three_times(&self) -> Self {
        self.three_times()
    }

    fn times_pow2(&self, exponent: usize) -> Self {
        self.times_pow2(exponent)
    }

    fn negate(&self) -> Self {
        self.negate()
    }

    fn normalize(&self) -> Self {
        self.normalize()
    }
}

impl PartialEq for SecP256R1Point {
    fn eq(&self, other: &Self) -> bool {
        if !(Arc::ptr_eq(&self.curve, &other.curve) || self.curve == other.curve) {
            return false;
        }
        let (Some(left), Some(right)) = (&self.coordinates, &other.coordinates) else {
            return self.is_infinity() && other.is_infinity();
        };
        let (left_x, left_y) = scale_affine(&left.x, &left.y, &right.z);
        let (right_x, right_y) = scale_affine(&right.x, &right.y, &left.z);
        left_x == right_x && left_y == right_y
    }
}

impl Eq for SecP256R1Point {}

impl Add for &SecP256R1Point {
    type Output = SecP256R1Point;

    fn add(self, rhs: Self) -> Self::Output {
        self.add_point(rhs)
    }
}

impl Neg for &SecP256R1Point {
    type Output = SecP256R1Point;

    fn neg(self) -> Self::Output {
        self.negate()
    }
}

impl core::fmt::Debug for SecP256R1Point {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Some(point) = &self.coordinates else {
            return formatter.write_str("SecP256R1Point(infinity)");
        };
        formatter
            .debug_struct("SecP256R1Point")
            .field("x", &point.x)
            .field("y", &point.y)
            .field("z", &point.z)
            .finish()
    }
}
