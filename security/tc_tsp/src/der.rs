use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

use crate::TspError;

// bytes 裡剛好一個結構，後面沒有東西
pub(crate) fn decode_all<T: Decode>(bytes: &[u8]) -> Result<T, TspError> {
    let (used, value) = T::decode(bytes, &DecodingOptions::default())?;
    if used != bytes.len() {
        return Err(Asn1Error::TrailingData.into());
    }
    Ok(value)
}

// 以 DER 重新編碼後照 U 解讀
pub(crate) fn convert<T: Encode, U: Decode>(value: &T) -> Result<U, TspError> {
    decode_all(&value.encode_to_vec(&EncodingOptions::DER)?)
}
