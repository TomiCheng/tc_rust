mod plain;
mod standard;

pub use plain::PlainDsaEncoding;
pub use standard::StandardDsaEncoding;

use crate::DsaEncodingError;
use alloc::vec::Vec;
use tc_bigint::{ArrayEncoding, PaddedBigUint};

/// 去掉前導零的大端序位元組，零是空的。變動時間：只能用於公開值。
fn magnitude(value: &PaddedBigUint) -> Vec<u8> {
    let bytes = ArrayEncoding::<u8>::to_be(value);
    let start = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

/// BC 的 `CheckValue`：`value` 要小於 `order`。變動時間：只能用於公開值。
fn check(order: &PaddedBigUint, value: &PaddedBigUint) -> Result<(), DsaEncodingError> {
    if value >= order {
        return Err(DsaEncodingError::ValueOutOfRange);
    }
    Ok(())
}
