//! 變動時間：只能用於公開值。原始整數依來源型別寬度建構，切片依輸入長度建構。
//! `ArrayEncoding` 的一般輸出保留整個儲存寬度；`to_unsigned_*` 輸出最短表示。
//! 一般 caller-buffer 寫入完整寬度，無號 magnitude 寫入最短表示；只改動回傳長度的前綴。
//! 既有具名 `write_be_bytes` 仍保留原契約；trait 寫入請以 `ArrayEncoding::write_be_bytes` 呼叫。
//!
//! # Examples
//! ```
//! use tc_bigint::{PaddedBigUint, FromPrimitive, ToPrimitive, ArrayEncoding, limbs_for_bits};
//! let value = PaddedBigUint::from_u64(7).unwrap();
//! assert_eq!(value.len(), limbs_for_bits(64));
//! assert_eq!(value.to_u8(), Some(7));
//! let padded = <PaddedBigUint as ArrayEncoding>::from_be_bytes(&[0, 0, 7]).unwrap();
//! assert_eq!(padded.len(), limbs_for_bits(24));
//! assert_eq!(padded.to_unsigned_be_bytes(), [7]);
//! ```
use crate::{
    ArrayEncoding, BigUint, ConversionError, FromPrimitive, PaddedBigUint, ToPrimitive, Word,
    limbs_for_bits,
};
use alloc::{vec, vec::Vec};

macro_rules! from_unsigned {
    ($($method:ident: $ty:ty),* $(,)?) => {$ (
        /// 變動時間：只能用於公開值。依來源原始型別的位元數決定寬度。
        fn $method(value: $ty) -> Option<Self> {
            Self::from_le_bytes(&value.to_le_bytes(), limbs_for_bits(<$ty>::BITS as usize)).ok()
        }
    )*};
}
macro_rules! from_signed {
    ($($method:ident: $ty:ty => $unsigned:ty),* $(,)?) => {$ (
        /// 變動時間：只能用於公開值。負值回 `None`；非負值保留來源型別寬度。
        fn $method(value: $ty) -> Option<Self> {
            let value = <$unsigned>::try_from(value).ok()?;
            Self::from_le_bytes(&value.to_le_bytes(), limbs_for_bits(<$ty>::BITS as usize)).ok()
        }
    )*};
}
/// 變動時間：只能用於公開值。整數輸入依原始型別寬度建構；負值不接受。
/// 浮點數沿用 trait 的有限範圍與截去小數規則。
impl FromPrimitive for PaddedBigUint {
    from_unsigned!(from_u8: u8, from_u16: u16, from_u32: u32, from_u64: u64, from_u128: u128, from_usize: usize);
    from_signed!(from_i8: i8 => u8, from_i16: i16 => u16, from_i32: i32 => u32,
        from_i64: i64 => u64, from_i128: i128 => u128, from_isize: isize => usize);
}
/// 變動時間：只能用於公開值。原始型別轉換委派 `BigUint`，放不下回 `None`。
impl ToPrimitive for PaddedBigUint {
    fn to_i64(&self) -> Option<i64> {
        self.to_big_uint().to_i64()
    }
    fn to_i128(&self) -> Option<i128> {
        self.to_big_uint().to_i128()
    }
    fn to_u64(&self) -> Option<u64> {
        self.to_big_uint().to_u64()
    }
    fn to_u128(&self) -> Option<u128> {
        self.to_big_uint().to_u128()
    }
}
macro_rules! primitive_from {
    ($($ty:ty),* $(,)?) => {$ (
        /// 變動時間：只能用於公開值。依來源原始型別的位元數決定寬度。
        impl From<$ty> for PaddedBigUint {
            fn from(value: $ty) -> Self {
                Self::from_le_bytes(&value.to_le_bytes(), limbs_for_bits(<$ty>::BITS as usize)).expect("來源型別寬度足夠")
            }
        }
    )*};
}
primitive_from!(u8, u16, u32, u64, u128, usize);

macro_rules! decode {
    ($name:ident, $ty:ty, $delegate:ident) => {
        /// 變動時間：只能用於公開值。依輸入切片長度決定寬度，保留前導零。
        fn $name(input: &[$ty]) -> Result<Self, ConversionError> {
            let bits = input
                .len()
                .checked_mul(<$ty>::BITS as usize)
                .expect("輸入寬度溢位");
            Self::from_big_uint(&BigUint::$delegate(input), limbs_for_bits(bits))
        }
    };
}
macro_rules! write {
    ($name:ident, $ty:ty, $delegate:ident) => {
        /// 變動時間：只能用於公開值。寫入最短表示，只改動回傳長度的前綴。
        fn $name(&self, output: &mut [$ty]) -> Result<usize, ConversionError> {
            self.to_big_uint().$delegate(output)
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
impl ArrayEncoding for PaddedBigUint {
    type DecodeError = ConversionError;
    decode!(from_le_bytes, u8, from_le_bytes);
    decode!(from_le_u32, u32, from_le_u32);
    decode!(from_le_u64, u64, from_le_u64);
    decode!(from_be_bytes, u8, from_be_bytes);
    decode!(from_be_u32, u32, from_be_u32);
    decode!(from_be_u64, u64, from_be_u64);
    decode!(from_unsigned_le_bytes, u8, from_le_bytes);
    decode!(from_unsigned_le_u32, u32, from_le_u32);
    decode!(from_unsigned_le_u64, u64, from_le_u64);
    decode!(from_unsigned_be_bytes, u8, from_be_bytes);
    decode!(from_unsigned_be_u32, u32, from_be_u32);
    decode!(from_unsigned_be_u64, u64, from_be_u64);
    write_full!(write_le_bytes, u8, false);
    write_full!(write_le_u32, u32, false);
    write_full!(write_le_u64, u64, false);
    write_full!(write_be_bytes, u8, true);
    write_full!(write_be_u32, u32, true);
    write_full!(write_be_u64, u64, true);
    write!(write_unsigned_le_bytes, u8, write_le_bytes);
    write!(write_unsigned_le_u32, u32, write_le_u32);
    write!(write_unsigned_le_u64, u64, write_le_u64);
    write!(write_unsigned_be_bytes, u8, write_be_bytes);
    write!(write_unsigned_be_u32, u32, write_be_u32);
    write!(write_unsigned_be_u64, u64, write_be_u64);
    fn byte_length(&self) -> usize {
        self.len() * size_of::<Word>()
    }
    fn byte_length_unsigned(&self) -> usize {
        PaddedBigUint::byte_length_unsigned(self)
    }
    fn u32_length(&self) -> usize {
        (self.len() * Word::BITS as usize).div_ceil(32)
    }
    fn u32_length_unsigned(&self) -> usize {
        self.bit_len().div_ceil(32).max(1)
    }
    fn u64_length(&self) -> usize {
        (self.len() * Word::BITS as usize).div_ceil(64)
    }
    fn u64_length_unsigned(&self) -> usize {
        self.bit_len().div_ceil(64).max(1)
    }
    full_output!(to_le_bytes, u8, write_le_bytes);
    full_output!(to_le_u32, u32, write_le_u32);
    full_output!(to_le_u64, u64, write_le_u64);
    full_output!(to_be_bytes, u8, write_be_bytes);
    full_output!(to_be_u32, u32, write_be_u32);
    full_output!(to_be_u64, u64, write_be_u64);
}
