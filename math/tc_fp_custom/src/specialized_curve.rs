//! 靜態 SEC 質數曲線的參數、SEC1 解碼與 `Curve` 實作。

use alloc::sync::Arc;
use core::marker::PhantomData;

use tc_bigint::{ArrayEncoding, BitOps, FromPrimitive};
use tc_ec_core::{CoordinateSystem, Curve, PointDecodeError};

use crate::specialized_field::{PrimeFieldSpec, SpecializedFieldElement};
use crate::specialized_point::SpecializedPoint;

/// 編譯期參數的短 Weierstrass 質數曲線。
#[derive(Clone)]
#[doc(hidden)]
pub struct SpecializedCurve<S, const N: usize>
where
    S: PrimeFieldSpec<N>,
{
    q: S::Integer,
    a: SpecializedFieldElement<S, N>,
    b: SpecializedFieldElement<S, N>,
    order: S::Integer,
    cofactor: S::Integer,
    marker: PhantomData<S>,
}

impl<S: PrimeFieldSpec<N>, const N: usize> SpecializedCurve<S, N> {
    /// 建立固定參數曲線。
    pub fn new() -> Self {
        Self {
            q: integer::<S, N>(&S::P),
            a: SpecializedFieldElement::from_words(S::A).expect("curve a is canonical"),
            b: SpecializedFieldElement::from_words(S::B).expect("curve b is canonical"),
            order: S::Integer::from_unsigned_le_u32(&S::ORDER)
                .unwrap_or_else(|_| panic!("{} order fits its integer type", S::NAME)),
            cofactor: S::Integer::from_u32(1).expect("one fits every curve integer"),
            marker: PhantomData,
        }
    }

    /// 體域質數。
    pub fn q(&self) -> &S::Integer {
        &self.q
    }

    /// 曲線係數 `a`。
    pub fn a(&self) -> &SpecializedFieldElement<S, N> {
        &self.a
    }

    /// 曲線係數 `b`。
    pub fn b(&self) -> &SpecializedFieldElement<S, N> {
        &self.b
    }

    /// 基點子群階。
    pub fn order(&self) -> &S::Integer {
        &self.order
    }

    /// Cofactor，這批 SEC 質數曲線固定為一。
    pub fn cofactor(&self) -> &S::Integer {
        &self.cofactor
    }

    /// 由一般整數建立欄位元素。
    pub fn create_field_element(
        &self,
        value: &S::Integer,
    ) -> Option<SpecializedFieldElement<S, N>> {
        SpecializedFieldElement::from_integer(value)
    }

    /// 建立無窮遠點。
    pub fn infinity(self: &Arc<Self>) -> SpecializedPoint<S, N> {
        SpecializedPoint::infinity(Arc::clone(self))
    }

    /// 由 affine 整數座標建立點；只檢查座標範圍。
    pub fn create_point(
        self: &Arc<Self>,
        x: S::Integer,
        y: S::Integer,
    ) -> Option<SpecializedPoint<S, N>> {
        Some(SpecializedPoint::new(
            Arc::clone(self),
            self.create_field_element(&x)?,
            self.create_field_element(&y)?,
        ))
    }

    /// 從壓縮 X 座標還原點。
    pub fn decompress_point(
        self: &Arc<Self>,
        y_tilde: u8,
        x: S::Integer,
    ) -> Option<SpecializedPoint<S, N>> {
        if y_tilde > 1 {
            return None;
        }
        let x = self.create_field_element(&x)?;
        let rhs = &(&(&x.square() + self.a()) * &x) + self.b();
        let mut y = rhs.sqrt()?;
        if y.test_bit_zero() != (y_tilde == 1) {
            y = y.negate();
        }
        Some(SpecializedPoint::new(Arc::clone(self), x, y))
    }

    /// 解碼 SEC1 infinity、compressed、uncompressed 與 hybrid 格式。
    pub fn decode_point(
        self: &Arc<Self>,
        encoded: &[u8],
    ) -> Result<SpecializedPoint<S, N>, PointDecodeError> {
        let (&tag, body) = encoded.split_first().ok_or(PointDecodeError::Empty)?;
        match tag {
            0 if body.is_empty() => Ok(self.infinity()),
            0 => Err(PointDecodeError::InvalidLength),
            0x02 | 0x03 => {
                if body.len() != S::BYTES {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = decode_integer::<S, N>(body)?;
                self.decompress_point(tag & 1, x)
                    .filter(SpecializedPoint::is_valid)
                    .ok_or(PointDecodeError::NotOnCurve)
            }
            0x04 | 0x06 | 0x07 => {
                if body.len() != S::BYTES * 2 {
                    return Err(PointDecodeError::InvalidLength);
                }
                let x = decode_integer::<S, N>(&body[..S::BYTES])?;
                let y = decode_integer::<S, N>(&body[S::BYTES..])?;
                let point = self
                    .create_point(x, y)
                    .ok_or(PointDecodeError::CoordinateOutOfRange)?;
                if !point.is_valid() {
                    return Err(PointDecodeError::NotOnCurve);
                }
                if tag != 0x04
                    && point.raw_y().expect("decoded finite point").test_bit_zero()
                        != (tag & 1 == 1)
                {
                    return Err(PointDecodeError::InconsistentHybridY);
                }
                Ok(point)
            }
            _ => Err(PointDecodeError::UnknownEncoding(tag)),
        }
    }

    /// 檢查 affine 座標是否滿足曲線方程式。
    pub fn contains_affine(
        &self,
        x: &SpecializedFieldElement<S, N>,
        y: &SpecializedFieldElement<S, N>,
    ) -> bool {
        y.square() == &(&(&x.square() + self.a()) * x) + self.b()
    }
}

impl<S: PrimeFieldSpec<N>, const N: usize> Default for SpecializedCurve<S, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: PrimeFieldSpec<N>, const N: usize> PartialEq for SpecializedCurve<S, N> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<S: PrimeFieldSpec<N>, const N: usize> Eq for SpecializedCurve<S, N> {}

impl<S: PrimeFieldSpec<N>, const N: usize> core::fmt::Debug for SpecializedCurve<S, N> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct(S::NAME).finish_non_exhaustive()
    }
}

impl<S: PrimeFieldSpec<N>, const N: usize> Curve for SpecializedCurve<S, N> {
    type Field = SpecializedFieldElement<S, N>;
    type Point = SpecializedPoint<S, N>;
    type Scalar = S::Integer;

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
        SpecializedFieldElement::ZERO
    }

    fn one(&self) -> Self::Field {
        SpecializedFieldElement::ONE
    }

    fn identity(self: &Arc<Self>) -> Self::Point {
        self.infinity()
    }

    fn create_point(self: &Arc<Self>, x: Self::Field, y: Self::Field) -> Self::Point {
        SpecializedPoint::new(Arc::clone(self), x, y)
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
        scalar.bit_length() == 0
    }

    fn scalar_shr1(scalar: &Self::Scalar) -> Self::Scalar {
        scalar.clone() >> 1
    }

    fn scalar_shr(scalar: &Self::Scalar, count: usize) -> Self::Scalar {
        if count >= scalar.bit_length() {
            S::Integer::from_u32(0).expect("zero fits every scalar type")
        } else {
            scalar.clone() >> count
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
        let magnitude =
            S::Integer::from_u32(digit.unsigned_abs()).expect("wNAF digit fits scalar type");
        if digit < 0 {
            scalar.clone() + &magnitude
        } else {
            scalar.clone() - &magnitude
        }
    }
}

/// 建立規格對應的曲線與標準生成點。
#[doc(hidden)]
pub fn named_curve<S: PrimeFieldSpec<N>, const N: usize>()
-> (Arc<SpecializedCurve<S, N>>, SpecializedPoint<S, N>) {
    let curve = Arc::new(SpecializedCurve::new());
    let generator = SpecializedPoint::new(
        Arc::clone(&curve),
        SpecializedFieldElement::from_words(S::GX).expect("generator x is canonical"),
        SpecializedFieldElement::from_words(S::GY).expect("generator y is canonical"),
    );
    debug_assert!(generator.is_valid());
    (curve, generator)
}

fn integer<S: PrimeFieldSpec<N>, const N: usize>(words: &[u32; N]) -> S::Integer {
    S::Integer::from_unsigned_le_u32(words)
        .unwrap_or_else(|_| panic!("{} constant fits its integer type", S::NAME))
}

fn decode_integer<S: PrimeFieldSpec<N>, const N: usize>(
    bytes: &[u8],
) -> Result<S::Integer, PointDecodeError> {
    let value = S::Integer::from_unsigned_be_bytes(bytes)
        .map_err(|_| PointDecodeError::CoordinateOutOfRange)?;
    if value >= integer::<S, N>(&S::P) {
        return Err(PointDecodeError::CoordinateOutOfRange);
    }
    Ok(value)
}
