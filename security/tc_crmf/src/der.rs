use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

use crate::CrmfError;

pub(crate) fn decode<T: Decode + Encode>(bytes: &[u8]) -> Result<T, CrmfError> {
    let (used, value) = T::decode_der(bytes, &DecodingOptions::default())?;
    if used != bytes.len() {
        return Err(Asn1Error::TrailingData.into());
    }
    if value.encode_to_vec(&EncodingOptions::DER)? != bytes {
        return Err(CrmfError::Invalid("noncanonical CRMF DER"));
    }
    Ok(value)
}

pub(crate) fn convert<T: Decode + Encode>(value: &(impl Encode + ?Sized)) -> Result<T, CrmfError> {
    decode(&value.encode_to_vec(&EncodingOptions::DER)?)
}
