use tc_asn1::{Asn1Error, Asn1Object, Decode, DecodingOptions, Encode, EncodingOptions};

use crate::PkcsError;

// The structure `bytes` hold, with nothing after it
pub(crate) fn decode_all<T: Decode>(bytes: &[u8]) -> Result<T, PkcsError> {
    let (used, value) = T::decode(bytes, &DecodingOptions::default())?;
    if used != bytes.len() {
        return Err(Asn1Error::TrailingData.into());
    }
    Ok(value)
}

// The parameters of an AlgorithmIdentifier, which have no schema there, read as `T`
pub(crate) fn reparse<T: Decode>(parameters: Option<&Asn1Object>) -> Result<T, PkcsError> {
    let parameters = parameters.ok_or(PkcsError::InvalidEncryptionParams)?;
    decode_all(&parameters.encode_to_vec(&EncodingOptions::DER)?)
}

// `value` as the parameters of an AlgorithmIdentifier
pub(crate) fn to_object<T: Encode>(value: &T) -> Result<Asn1Object, PkcsError> {
    decode_all(&value.encode_to_vec(&EncodingOptions::DER)?)
}
