//! Standard conversions to and from [`BigInt`].

use core::mem::size_of;
use core::str::FromStr;

use super::BigInt;
use crate::error::{ParseBigIntError, TryFromBigIntError};

impl FromStr for BigInt {
    type Err = ParseBigIntError;

    /// Parses in radix 10（讓 `"123".parse::<BigInt>()` 可用）。
    fn from_str(s: &str) -> Result<BigInt, ParseBigIntError> {
        BigInt::from_str_radix(s, 10)
    }
}

/// 為每個固定寬度整數型別生成無損的 `From<$t> for BigInt`，委派給對應建構函式。
macro_rules! impl_from_primitive {
    ($($t:ty => $ctor:ident),* $(,)?) => {
        $(
            impl From<$t> for BigInt {
                /// 無損轉換（固定寬度整數必可表示）。
                fn from(value: $t) -> Self {
                    BigInt::$ctor(value)
                }
            }
        )*
    };
}

impl_from_primitive! {
    u8 => from_u8, u16 => from_u16, u32 => from_u32, u64 => from_u64, u128 => from_u128,
    i8 => from_i8, i16 => from_i16, i32 => from_i32, i64 => from_i64, i128 => from_i128,
}

/// 為每個無號整數型別生成 `TryFrom<&BigInt>`：負數或超出範圍回 `Err`。
macro_rules! impl_try_from_big_unsigned {
    ($($t:ty),* $(,)?) => {
        $(
            impl TryFrom<&BigInt> for $t {
                type Error = TryFromBigIntError;

                fn try_from(value: &BigInt) -> Result<$t, TryFromBigIntError> {
                    if value.sign() < 0 {
                        return Err(TryFromBigIntError::new()); // 負數無法轉無號
                    }
                    const BYTES: usize = size_of::<$t>();
                    let n = value.byte_length_unsigned();
                    if n > BYTES {
                        return Err(TryFromBigIntError::new()); // 位元組數超出目標
                    }
                    // magnitude 位元組右對齊寫進固定寬度 buffer，上方補 0
                    let mut buf = [0u8; BYTES];
                    value.to_bytes_be_unsigned_into(&mut buf[BYTES - n..]);
                    Ok(<$t>::from_be_bytes(buf))
                }
            }
        )*
    };
}

/// 為每個有號整數型別生成 `TryFrom<&BigInt>`：超出範圍回 `Err`。
macro_rules! impl_try_from_big_signed {
    ($($t:ty),* $(,)?) => {
        $(
            impl TryFrom<&BigInt> for $t {
                type Error = TryFromBigIntError;

                fn try_from(value: &BigInt) -> Result<$t, TryFromBigIntError> {
                    const BYTES: usize = size_of::<$t>();
                    let n = value.byte_length();
                    if n > BYTES {
                        return Err(TryFromBigIntError::new());
                    }
                    // 兩補數位元組右對齊寫入；上方以符號延伸填滿（負 0xFF、非負 0x00）
                    let mut buf = if value.sign() < 0 { [0xFFu8; BYTES] } else { [0u8; BYTES] };
                    value.to_bytes_be_into(&mut buf[BYTES - n..]);
                    Ok(<$t>::from_be_bytes(buf))
                }
            }
        )*
    };
}

impl_try_from_big_unsigned!(u8, u16, u32, u64, u128);
impl_try_from_big_signed!(i8, i16, i32, i64, i128);
