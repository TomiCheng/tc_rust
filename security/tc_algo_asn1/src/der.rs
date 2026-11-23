use tc_asn1::{Asn1Error, Decode, DecodingOptions};

use crate::AlgoAsn1Error;

// bytes 裡的結構，後面不能有多餘的資料
pub(crate) fn decode_all<T: Decode>(bytes: &[u8]) -> Result<T, AlgoAsn1Error> {
    let (used, value) = T::decode(bytes, &DecodingOptions::default())?;
    if used != bytes.len() {
        return Err(Asn1Error::TrailingData.into());
    }
    Ok(value)
}
