//! 變動時間：只能用於公開值。二補數解碼依輸入寬度，無號輸入解讀為非負 magnitude。
//! 一般輸出保留完整儲存寬度；無號輸出是絕對值的最短 magnitude。
use crate::{
    ArrayEncoding, BigInt, ConversionError, FromPrimitive, PaddedBigInt, ToPrimitive, Word,
    limbs_for_bits,
};
use alloc::{vec, vec::Vec};

macro_rules! from_primitive {
    ($($method:ident: $ty:ty),* $(,)?) => {$ (
        /// 變動時間：只能用於公開值。保留來源型別位元數推得的 limb 寬度。
        /// 無號輸入若佔用該寬度的符號位，回 `None`。
        fn $method(value: $ty) -> Option<Self> {
            Self::from_big_int(&BigInt::from(value), limbs_for_bits(<$ty>::BITS as usize)).ok()
        }
    )*};
}
/// 變動時間：只能用於公開值。以來源型別寬度建構，超出有號範圍回 `None`。
impl FromPrimitive for PaddedBigInt {
    from_primitive!(from_i8: i8, from_i16: i16, from_i32: i32, from_i64: i64,
        from_i128: i128, from_isize: isize, from_u8: u8, from_u16: u16,
        from_u32: u32, from_u64: u64, from_u128: u128, from_usize: usize);
}
macro_rules! signed_from {
    ($($ty:ty),* $(,)?) => {$ (
        /// 變動時間：只能用於公開值。依來源有號型別位元數決定寬度。
        impl From<$ty> for PaddedBigInt {
            fn from(value: $ty) -> Self {
                Self::from_le_bytes(&value.to_le_bytes(), limbs_for_bits(<$ty>::BITS as usize))
                    .expect("來源有號型別寬度足夠")
            }
        }
    )*};
}
signed_from!(i8, i16, i32, i64, i128, isize);

/// 變動時間：只能用於公開值。保持同寬；最高位為一會變成負值，故回 `InputTooLarge`。
impl TryFrom<&crate::PaddedBigUint> for PaddedBigInt {
    type Error = ConversionError;
    fn try_from(value: &crate::PaddedBigUint) -> Result<Self, Self::Error> {
        let out = Self::from_limbs(value.as_limbs().into());
        if out.is_negative() {
            Err(ConversionError::InputTooLarge)
        } else {
            Ok(out)
        }
    }
}
/// 變動時間：只能用於公開值。保持同寬，不自動加寬容納符號位。
impl TryFrom<crate::PaddedBigUint> for PaddedBigInt {
    type Error = ConversionError;
    fn try_from(value: crate::PaddedBigUint) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}
/// 變動時間：只能用於公開值。非負值保持同寬，負值回 `NegativeValue`。
impl TryFrom<&PaddedBigInt> for crate::PaddedBigUint {
    type Error = ConversionError;
    fn try_from(value: &PaddedBigInt) -> Result<Self, Self::Error> {
        if value.is_negative() {
            Err(ConversionError::NegativeValue)
        } else {
            Ok(Self::from_limbs(value.limbs.clone()))
        }
    }
}
/// 變動時間：只能用於公開值。非負值保持同寬，負值回 `NegativeValue`。
impl TryFrom<PaddedBigInt> for crate::PaddedBigUint {
    type Error = ConversionError;
    fn try_from(value: PaddedBigInt) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

/// 變動時間：只能用於公開值。原始型別轉換委派 `BigInt`，放不下回 `None`。
impl ToPrimitive for PaddedBigInt {
    fn to_i64(&self) -> Option<i64> {
        self.to_big_int().to_i64()
    }
    fn to_i128(&self) -> Option<i128> {
        self.to_big_int().to_i128()
    }
    fn to_u64(&self) -> Option<u64> {
        self.to_big_int().to_u64()
    }
    fn to_u128(&self) -> Option<u128> {
        self.to_big_int().to_u128()
    }
}
macro_rules! decode {
    ($name:ident, $ty:ty, $delegate:ident) => {
        /// 變動時間：只能用於公開值。依輸入切片長度決定寬度，保留符號擴展位。
        fn $name(input: &[$ty]) -> Result<Self, ConversionError> {
            let bits = input
                .len()
                .checked_mul(<$ty>::BITS as usize)
                .expect("輸入寬度溢位");
            Self::from_big_int(&BigInt::$delegate(input), limbs_for_bits(bits))
        }
    };
}
macro_rules! write {
    ($name:ident, $ty:ty, $delegate:ident) => {
        /// 變動時間：只能用於公開值。寫入最短表示，只改動回傳長度的前綴。
        fn $name(&self, output: &mut [$ty]) -> Result<usize, ConversionError> {
            self.to_big_int().$delegate(output)
        }
    };
}
macro_rules! write_full {
    ($name:ident, $ty:ty, $big:literal) => {
        /// 變動時間：只能用於公開值。寫入完整儲存寬度，輸出多餘的尾端保持原狀。
        fn $name(&self, output: &mut [$ty]) -> Result<usize, ConversionError> {
            let length = (self.len() * Word::BITS as usize).div_ceil(<$ty>::BITS as usize);
            if output.len() < length {
                return Err(ConversionError::BufferTooSmall);
            }
            for source in 0..length {
                let mut unit = 0 as $ty;
                for byte in 0..size_of::<$ty>() {
                    unit |= (self.byte_at(source * size_of::<$ty>() + byte) as $ty) << (byte * 8);
                }
                let target = if $big { length - 1 - source } else { source };
                output[target] = unit;
            }
            Ok(length)
        }
    };
}
macro_rules! full_output {
    ($name:ident, $ty:ty, $writer:ident) => {
        /// 變動時間：只能用於公開值。輸出完整儲存寬度；零寬輸出空陣列。
        fn $name(&self) -> Vec<$ty> {
            let length = (self.len() * Word::BITS as usize).div_ceil(<$ty>::BITS as usize);
            let mut out = vec![0; length];
            if !out.is_empty() {
                <Self as ArrayEncoding>::$writer(self, &mut out).expect("完整寬度足夠");
            }
            out
        }
    };
}
/// 變動時間：只能用於公開值。解碼寬度由切片長度決定，不由有效數值決定。
/// 一般配置型輸出保留儲存寬度，無號 magnitude 輸出採最短表示（零為一單位）。
impl ArrayEncoding for PaddedBigInt {
    type DecodeError = ConversionError;
    decode!(from_le_bytes, u8, from_le_bytes);
    decode!(from_le_u32, u32, from_le_u32);
    decode!(from_le_u64, u64, from_le_u64);
    decode!(from_be_bytes, u8, from_be_bytes);
    decode!(from_be_u32, u32, from_be_u32);
    decode!(from_be_u64, u64, from_be_u64);
    decode!(from_unsigned_le_bytes, u8, from_unsigned_le_bytes);
    decode!(from_unsigned_le_u32, u32, from_unsigned_le_u32);
    decode!(from_unsigned_le_u64, u64, from_unsigned_le_u64);
    decode!(from_unsigned_be_bytes, u8, from_unsigned_be_bytes);
    decode!(from_unsigned_be_u32, u32, from_unsigned_be_u32);
    decode!(from_unsigned_be_u64, u64, from_unsigned_be_u64);
    write_full!(write_le_bytes, u8, false);
    write_full!(write_le_u32, u32, false);
    write_full!(write_le_u64, u64, false);
    write_full!(write_be_bytes, u8, true);
    write_full!(write_be_u32, u32, true);
    write_full!(write_be_u64, u64, true);
    write!(write_unsigned_le_bytes, u8, write_unsigned_le_bytes);
    write!(write_unsigned_le_u32, u32, write_unsigned_le_u32);
    write!(write_unsigned_le_u64, u64, write_unsigned_le_u64);
    write!(write_unsigned_be_bytes, u8, write_unsigned_be_bytes);
    write!(write_unsigned_be_u32, u32, write_unsigned_be_u32);
    write!(write_unsigned_be_u64, u64, write_unsigned_be_u64);
    fn byte_length(&self) -> usize {
        self.len() * size_of::<Word>()
    }
    fn byte_length_unsigned(&self) -> usize {
        self.to_big_int().byte_length_unsigned()
    }
    fn u32_length(&self) -> usize {
        (self.len() * Word::BITS as usize).div_ceil(32)
    }
    fn u32_length_unsigned(&self) -> usize {
        self.to_big_int().u32_length_unsigned()
    }
    fn u64_length(&self) -> usize {
        (self.len() * Word::BITS as usize).div_ceil(64)
    }
    fn u64_length_unsigned(&self) -> usize {
        self.to_big_int().u64_length_unsigned()
    }
    full_output!(to_le_bytes, u8, write_le_bytes);
    full_output!(to_le_u32, u32, write_le_u32);
    full_output!(to_le_u64, u64, write_le_u64);
    full_output!(to_be_bytes, u8, write_be_bytes);
    full_output!(to_be_u32, u32, write_be_u32);
    full_output!(to_be_u64, u64, write_be_u64);
}
