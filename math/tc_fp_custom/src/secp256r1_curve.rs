//! secp256r1 的固定參數曲線與 SEC 1 解碼。

use alloc::sync::Arc;

use tc_bigint::U256;
use tc_ec_core::{CoordinateSystem, Curve, PointDecodeError};

use crate::{SecP256R1Field, SecP256R1FieldElement, SecP256R1Point};

const A: [u32; 8] = [
    0xffff_fffc,
    0xffff_ffff,
    0xffff_ffff,
    0,
    0,
    0,
    1,
    0xffff_ffff,
];
const B: [u32; 8] = [
    0x27d2_604b,
    0x3bce_3c3e,
    0xcc53_b0f6,
    0x651d_06b0,
    0x7698_86bc,
    0xb3eb_bd55,
    0xaa3a_93e7,
    0x5ac6_35d8,
];
const ORDER: [u32; 8] = [
    0xfc63_2551,
    0xf3b9_cac2,
    0xa717_9e84,
    0xbce6_faad,
    0xffff_ffff,
    0xffff_ffff,
    0,
    0xffff_ffff,
];
const GX: [u32; 8] = [
    0xd898_c296,
    0xf4a1_3945,
    0x2deb_33a0,
    0x7703_7d81,
    0x63a4_40f2,
    0xf8bc_e6e5,
    0xe12c_4247,
    0x6b17_d1f2,
];
const GY: [u32; 8] = [
    0x37bf_51f5,
    0xcbb6_4068,
    0x6b31_5ece,
    0x2bce_3357,
    0x7c0f_9e16,
    0x8ee7_eb4a,
    0xfe1a_7f9b,
    0x4fe3_42e2,
];

/// 使用固定 P-256 欄位與 Jacobian 點的 secp256r1 曲線。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecP256R1Curve {
    q: U256,
    a: SecP256R1FieldElement,
    b: SecP256R1FieldElement,
    order: U256,
    cofactor: U256,
}

impl SecP256R1Curve {
    /// 建立固定參數的 secp256r1 曲線。
    pub fn new() -> Self {
        Self {
            q: uint(&SecP256R1Field::P),
            a: SecP256R1FieldElement(A),
            b: SecP256R1FieldElement(B),
            order: uint(&ORDER),
            cofactor: U256::from(1_u8),
        }
    }

    /// 體域質數。
    pub fn q(&self) -> &U256 {
        &self.q
    }

    /// 曲線係數 `a = -3 mod p`。
    pub fn a(&self) -> &SecP256R1FieldElement {
        &self.a
    }

    /// 曲線係數 `b`。
    pub fn b(&self) -> &SecP256R1FieldElement {
        &self.b
    }

    /// 生成子群階。
    pub fn order(&self) -> &U256 {
        &self.order
    }

    /// Cofactor，固定為一。
    pub fn cofactor(&self) -> &U256 {
        &self.cofactor
    }

    /// 由一般整數建立欄位元素。
    pub fn create_field_element(&self, value: &U256) -> Option<SecP256R1FieldElement> {
        SecP256R1FieldElement::from_uint(value)
    }

    /// 建立無窮遠點。
    pub fn infinity(self: &Arc<Self>) -> SecP256R1Point {
        SecP256R1Point::infinity(Arc::clone(self))
    }

    /// 由 affine 整數座標建立點；只檢查座標範圍。
    pub fn create_point(self: &Arc<Self>, x: U256, y: U256) -> Option<SecP256R1Point> {
        Some(SecP256R1Point::new(
            Arc::clone(self),
            self.create_field_element(&x)?,
            self.create_field_element(&y)?,
        ))
    }

    /// 由壓縮 X 座標還原點。
    pub fn decompress_point(self: &Arc<Self>, y_tilde: u8, x: U256) -> Option<SecP256R1Point> {
        if y_tilde > 1 {
            return None;
        }
        let x = self.create_field_element(&x)?;
        let rhs = &(&(&x.square() + self.a()) * &x) + self.b();
        let mut y = rhs.sqrt()?;
        if y.test_bit_zero() != (y_tilde == 1) {
            y = y.negate();
        }
        Some(SecP256R1Point::new(Arc::clone(self), x, y))
    }

    /// 解碼 SEC 1 infinity、compressed、uncompressed 與 hybrid 格式。
    pub fn decode_point(
        self: &Arc<Self>,
        encoded: &[u8],
    ) -> Result<SecP256R1Point, PointDecodeError> {
        let (&tag, body) = encoded.split_first().ok_or(PointDecodeError::Empty)?;
        match tag {
            0 if body.is_empty() => Ok(self.infinity()),
            0 => Err(PointDecodeError::InvalidLength),
            0x02 | 0x03 => {
                if body.len() != 32 {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = decode_coordinate(body)?;
                self.decompress_point(tag & 1, x)
                    .ok_or(PointDecodeError::NotOnCurve)
            }
            0x04 | 0x06 | 0x07 => {
                if body.len() != 64 {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = self
                    .create_field_element(&decode_coordinate(&body[..32])?)
                    .ok_or(PointDecodeError::CoordinateOutOfRange)?;
                let y = self
                    .create_field_element(&decode_coordinate(&body[32..])?)
                    .ok_or(PointDecodeError::CoordinateOutOfRange)?;
                if tag >= 0x06 && y.test_bit_zero() != (tag == 0x07) {
                    return Err(PointDecodeError::InconsistentHybridY);
                }
                if !self.contains_affine(&x, &y) {
                    return Err(PointDecodeError::NotOnCurve);
                }
                Ok(SecP256R1Point::new(Arc::clone(self), x, y))
            }
            other => Err(PointDecodeError::UnknownEncoding(other)),
        }
    }

    pub(crate) fn contains_affine(
        &self,
        x: &SecP256R1FieldElement,
        y: &SecP256R1FieldElement,
    ) -> bool {
        y.square() == &(&(&x.square() + self.a()) * x) + self.b()
    }
}

impl Default for SecP256R1Curve {
    fn default() -> Self {
        Self::new()
    }
}

impl Curve for SecP256R1Curve {
    type Field = SecP256R1FieldElement;
    type Point = SecP256R1Point;
    type Scalar = U256;

    fn a(&self) -> &Self::Field {
        self.a()
    }

    fn b(&self) -> &Self::Field {
        self.b()
    }

    fn order(&self) -> Option<&Self::Scalar> {
        Some(self.order())
    }

    fn cofactor(&self) -> Option<&Self::Scalar> {
        Some(self.cofactor())
    }

    fn zero(&self) -> Self::Field {
        SecP256R1FieldElement::ZERO
    }

    fn one(&self) -> Self::Field {
        SecP256R1FieldElement::ONE
    }

    fn identity(self: &Arc<Self>) -> Self::Point {
        self.infinity()
    }

    fn create_point(self: &Arc<Self>, x: Self::Field, y: Self::Field) -> Self::Point {
        SecP256R1Point::new(Arc::clone(self), x, y)
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        CoordinateSystem::Jacobian
    }

    fn scalar_bit_length(scalar: &Self::Scalar) -> usize {
        scalar.bit_length()
    }

    fn scalar_test_bit(scalar: &Self::Scalar, index: usize) -> bool {
        scalar.test_bit(index)
    }

    fn scalar_is_zero(scalar: &Self::Scalar) -> bool {
        scalar.is_zero()
    }

    fn scalar_shr1(scalar: &Self::Scalar) -> Self::Scalar {
        *scalar >> 1
    }

    fn scalar_shr(scalar: &Self::Scalar, count: usize) -> Self::Scalar {
        if count >= scalar.bit_length() {
            U256::from(0_u8)
        } else {
            *scalar >> count
        }
    }

    fn scalar_low_bits(scalar: &Self::Scalar, width: usize) -> u32 {
        assert!(width <= 32, "scalar low-bit width exceeds u32");
        let mut low = 0_u32;
        for bit in 0..width {
            if scalar.test_bit(bit) {
                low |= 1 << bit;
            }
        }
        low
    }

    fn scalar_sub_digit(scalar: &Self::Scalar, digit: i32) -> Self::Scalar {
        let magnitude = U256::from(digit.unsigned_abs());
        if digit < 0 {
            *scalar + magnitude
        } else {
            *scalar - magnitude
        }
    }
}

/// 建立 secp256r1 曲線與標準生成點。
pub fn secp256r1() -> (Arc<SecP256R1Curve>, SecP256R1Point) {
    let curve = Arc::new(SecP256R1Curve::new());
    let generator = SecP256R1Point::new(
        Arc::clone(&curve),
        SecP256R1FieldElement(GX),
        SecP256R1FieldElement(GY),
    );
    (curve, generator)
}

fn uint(words: &[u32; 8]) -> U256 {
    U256::from_le_u32(words).expect("eight u32 words fit U256")
}

fn decode_coordinate(bytes: &[u8]) -> Result<U256, PointDecodeError> {
    let value = U256::from_be_bytes(bytes).map_err(|_| PointDecodeError::CoordinateOutOfRange)?;
    if value >= uint(&SecP256R1Field::P) {
        return Err(PointDecodeError::CoordinateOutOfRange);
    }
    Ok(value)
}
