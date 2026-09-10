//! 變動時間：只能用於公開值。解析與格式化委派 `BigInt`。
//! 解析寬度由數值決定，需要特定寬度請接 [`PaddedBigInt::resize`]。
//!
//! # Examples
//! ```
//! use tc_bigint::{PaddedBigInt, Num, ToStrRadix};
//! let value = PaddedBigInt::from_str_radix("ff", 16).unwrap().resize(4).unwrap();
//! assert_eq!(value.len(), 4);
//! assert_eq!(value.to_str_radix(10), "255");
//! assert_eq!(format!("{value:04x}"), "00ff");
//! ```
use super::ops::public_result;
use crate::{BigInt, Num, PaddedBigInt, ParseBigIntError, ToStrRadix};
use alloc::string::String;
use core::{fmt, str::FromStr};

/// 變動時間：只能用於公開值。寬度由數值決定，需要特定寬度請接 `resize`。
impl Num for PaddedBigInt {
    type FromStrRadixErr = ParseBigIntError;
    fn from_str_radix(value: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        let value = BigInt::from_str_radix(value, radix)?;
        let width = value.as_limbs().len();
        Ok(public_result(value, width))
    }
}
/// 變動時間：只能用於公開值。十進位解析；寬度由數值決定，需要特定寬度請接 `resize`。
impl FromStr for PaddedBigInt {
    type Err = ParseBigIntError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_str_radix(value, 10)
    }
}
/// 變動時間：只能用於公開值。格式化不保留儲存用的符號擴展位。
impl ToStrRadix for PaddedBigInt {
    fn to_str_radix(&self, radix: u32) -> String {
        self.to_big_int().to_str_radix(radix)
    }
}
macro_rules! formatting {
    ($trait:ident) => {
        /// 變動時間：只能用於公開值。會輸出完整數值，秘密值不可格式化。
        impl fmt::$trait for PaddedBigInt {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::$trait::fmt(&self.to_big_int(), f)
            }
        }
    };
}
formatting!(Display);
formatting!(Binary);
formatting!(Octal);
formatting!(LowerHex);
formatting!(UpperHex);
