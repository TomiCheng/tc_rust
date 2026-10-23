use tc_asn1::{Asn1Error, Decode, DecodingOptions};

use crate::AnyError;

/// 整段 bytes 解成一個值；結尾多出的 bytes 視為錯誤。
pub(super) fn decode_all<T: Decode>(bytes: &[u8]) -> Result<T, AnyError> {
    let (consumed, value) = T::decode(bytes, &DecodingOptions::default()).map_err(AnyError::new)?;
    if consumed != bytes.len() {
        return Err(AnyError::new(Asn1Error::TrailingData));
    }
    Ok(value)
}
