use tc_asn1::{Asn1Object, Decode, DecodingOptions, Encode, EncodingOptions};

use crate::OperatorError;

pub(super) fn reparse<T: Decode>(parameters: &Asn1Object) -> Result<T, OperatorError> {
    let der = parameters.encode_to_vec(&EncodingOptions::DER)?;
    Ok(T::decode(&der, &DecodingOptions::default())?.1)
}

pub(super) fn to_object<T: Encode>(value: &T) -> Result<Asn1Object, OperatorError> {
    let der = value.encode_to_vec(&EncodingOptions::DER)?;
    Ok(Asn1Object::decode(&der, &DecodingOptions::default())?.1)
}
