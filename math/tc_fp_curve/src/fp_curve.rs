//! 以 `BigUint` 表示參數的短 Weierstrass 質數曲線。
//!
//! 曲線保存一份共享的 Montgomery 參數；由曲線建立的係數、座標與暫存體域
//! 元素都透過同一份參數運算。這一層目前刻意只支援 affine 座標，方便先與
//! 舊 `tc_ec` 建立逐位元 oracle，再於後續加入投影座標最佳化。

use alloc::sync::Arc;

use rand_core::Rng;
use tc_bigint::{BigUint, NonZero, RandomMod};

use crate::fp_field_element::{FpField, FpFieldElement};
use crate::{CoordinateSystem, FpPoint, PointDecodeError};

/// 質數體 `GF(q)` 上的短 Weierstrass 曲線 `y² = x³ + ax + b`。
#[derive(Clone)]
pub struct FpCurve {
    field: Arc<FpField>,
    a: FpFieldElement,
    b: FpFieldElement,
    order: Option<BigUint>,
    cofactor: Option<BigUint>,
    coordinate_system: CoordinateSystem,
}

impl FpCurve {
    /// 建立曲線並預先計算共用的 Montgomery 參數。
    ///
    /// # Panics
    ///
    /// `q` 為偶數，或 `a`、`b` 不在 `[0, q)` 時會 panic。
    pub fn new(
        q: BigUint,
        a: BigUint,
        b: BigUint,
        order: Option<BigUint>,
        cofactor: Option<BigUint>,
    ) -> Self {
        let field = FpField::new(q);
        let a = field.element(&a);
        let b = field.element(&b);
        Self {
            field,
            a,
            b,
            order,
            cofactor,
            coordinate_system: CoordinateSystem::Affine,
        }
    }

    /// 在本曲線的體域內建立元素。
    pub fn create_field_element(&self, value: BigUint) -> FpFieldElement {
        self.field.element(&value)
    }

    /// 回傳體域質數 `q`。
    pub fn q(&self) -> &BigUint {
        self.field.q()
    }

    /// 回傳曲線係數 `a`。
    pub fn a(&self) -> &FpFieldElement {
        &self.a
    }

    /// 回傳曲線係數 `b`。
    pub fn b(&self) -> &FpFieldElement {
        &self.b
    }

    /// 回傳已知的群階 `n`。
    pub fn order(&self) -> Option<&BigUint> {
        self.order.as_ref()
    }

    /// 回傳已知的 cofactor `h`。
    pub fn cofactor(&self) -> Option<&BigUint> {
        self.cofactor.as_ref()
    }

    /// 回傳體域質數的有效位元數。
    pub fn field_size(&self) -> usize {
        self.q().bits()
    }

    /// 判斷整數是否可直接成為本體域元素。
    pub fn is_valid_field_element(&self, value: &BigUint) -> bool {
        value < self.q()
    }

    /// 均勻取樣 `[0, q)`，並相乘兩份獨立樣本以沿用 BC 的時序鈍化策略。
    pub fn random_field_element<R: Rng + ?Sized>(&self, rng: &mut R) -> FpFieldElement {
        let modulus = NonZero::new(self.q().clone()).expect("curve prime is non-zero");
        let left = BigUint::random_mod_vartime(rng, &modulus);
        let right = BigUint::random_mod_vartime(rng, &modulus);
        &self.create_field_element(left) * &self.create_field_element(right)
    }

    /// 均勻取樣 `[1, q)`；兩份樣本都保證非零後再相乘。
    pub fn random_field_element_mult<R: Rng + ?Sized>(&self, rng: &mut R) -> FpFieldElement {
        let modulus = NonZero::new(self.q().clone()).expect("curve prime is non-zero");
        let sample = |rng: &mut R| loop {
            let value = BigUint::random_mod_vartime(rng, &modulus);
            if !value.is_zero() {
                break value;
            }
        };
        let left = sample(rng);
        let right = sample(rng);
        &self.create_field_element(left) * &self.create_field_element(right)
    }

    /// 回傳目前使用的座標系。
    pub fn coordinate_system(&self) -> CoordinateSystem {
        self.coordinate_system
    }

    /// 建立使用指定座標系的曲線設定。
    ///
    /// Step 2 的算術只實作 affine；其他值先保留為未來擴充入口。
    pub fn with_coordinate_system(mut self, coordinate_system: CoordinateSystem) -> Self {
        self.coordinate_system = coordinate_system;
        self
    }

    /// 回傳本曲線的無窮遠點。
    pub fn infinity(self: &Arc<Self>) -> FpPoint {
        FpPoint::infinity(Arc::clone(self))
    }

    /// 建立 affine 點；此函式只驗座標範圍，不主動驗曲線方程式。
    pub fn create_point(self: &Arc<Self>, x: BigUint, y: BigUint) -> FpPoint {
        FpPoint::new(
            Arc::clone(self),
            self.create_field_element(x),
            self.create_field_element(y),
        )
    }

    /// 由壓縮編碼的 X 座標與 Y 奇偶位元還原點。
    pub fn decompress_point(self: &Arc<Self>, y_tilde: u8, x: BigUint) -> Option<FpPoint> {
        if y_tilde > 1 || !self.is_valid_field_element(&x) {
            return None;
        }
        let x = self.create_field_element(x);
        let rhs = &(&(&x.square() + self.a()) * &x) + self.b();
        let y = rhs.sqrt()?;
        let y = if y.to_big_uint().test_bit(0) != (y_tilde == 1) {
            -&y
        } else {
            y
        };
        Some(FpPoint::new(Arc::clone(self), x, y))
    }

    /// 回傳一個體域元素的固定編碼長度。
    pub fn field_element_encoding_length(&self) -> usize {
        self.field_size().div_ceil(8)
    }

    /// 回傳 affine SEC 點編碼長度。
    pub fn affine_point_encoding_length(&self, compressed: bool) -> usize {
        let len = self.field_element_encoding_length();
        if compressed { 1 + len } else { 1 + 2 * len }
    }

    pub(crate) fn contains_affine(&self, x: &FpFieldElement, y: &FpFieldElement) -> bool {
        let rhs = &(&(&x.square() + self.a()) * x) + self.b();
        y.square() == rhs
    }

    fn parse_coordinate(&self, bytes: &[u8]) -> Result<FpFieldElement, PointDecodeError> {
        let value = BigUint::from_be_bytes(bytes);
        if !self.is_valid_field_element(&value) {
            return Err(PointDecodeError::CoordinateOutOfRange);
        }
        Ok(self.create_field_element(value))
    }

    /// 解碼 X9.62／SEC 1 的 infinity、compressed、uncompressed 與 hybrid 格式。
    pub fn decode_point(self: &Arc<Self>, encoded: &[u8]) -> Result<FpPoint, PointDecodeError> {
        let len = self.field_element_encoding_length();
        let (&tag, body) = encoded.split_first().ok_or(PointDecodeError::Empty)?;

        match tag {
            0x00 if body.is_empty() => Ok(self.infinity()),
            0x00 => Err(PointDecodeError::InvalidLength),
            0x02 | 0x03 => {
                if body.len() != len {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = BigUint::from_be_bytes(body);
                if !self.is_valid_field_element(&x) {
                    return Err(PointDecodeError::CoordinateOutOfRange);
                }
                self.decompress_point(tag & 1, x)
                    .ok_or(PointDecodeError::NotOnCurve)
            }
            0x04 | 0x06 | 0x07 => {
                if body.len() != 2 * len {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = self.parse_coordinate(&body[..len])?;
                let y = self.parse_coordinate(&body[len..])?;
                if tag >= 0x06 && y.to_big_uint().test_bit(0) != (tag == 0x07) {
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

impl PartialEq for FpCurve {
    fn eq(&self, other: &Self) -> bool {
        self.q() == other.q() && self.a == other.a && self.b == other.b
    }
}

impl Eq for FpCurve {}

impl core::fmt::Debug for FpCurve {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FpCurve")
            .field("q", self.q())
            .field("a", &self.a.to_big_uint())
            .field("b", &self.b.to_big_uint())
            .field("order", &self.order)
            .field("cofactor", &self.cofactor)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use rand_core::TryRng;

    struct SequenceRng(u64);

    impl TryRng for SequenceRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64()? as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            Ok(self.0)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                let bytes = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }

    fn curve17() -> Arc<FpCurve> {
        Arc::new(FpCurve::new(
            BigUint::from(17_u8),
            BigUint::from(2_u8),
            BigUint::from(2_u8),
            None,
            None,
        ))
    }

    #[test]
    fn sec_codec_round_trips_all_supported_forms() {
        let curve = curve17();
        let point = curve.create_point(BigUint::from(5_u8), BigUint::from(1_u8));
        for compressed in [false, true] {
            assert_eq!(
                curve.decode_point(&point.encode(compressed)).unwrap(),
                point
            );
        }
        assert_eq!(curve.decode_point(&[0]).unwrap(), curve.infinity());
        assert!(matches!(
            curve.decode_point(&[0x06, 5, 1]),
            Err(PointDecodeError::InconsistentHybridY)
        ));
    }

    #[test]
    fn random_elements_have_the_required_range() {
        let curve = curve17();
        let mut rng = SequenceRng(0xDEAD_BEEF);
        for _ in 0..32 {
            assert!(curve.random_field_element(&mut rng).to_big_uint() < *curve.q());
            assert!(!curve.random_field_element_mult(&mut rng).is_zero());
        }
    }
}
