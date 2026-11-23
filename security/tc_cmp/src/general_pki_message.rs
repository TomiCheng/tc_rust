use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_cmp::{PkiBody, PkiHeader, PkiMessage};

use crate::CmpError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneralPkiMessage {
    message: PkiMessage,
}

impl From<PkiMessage> for GeneralPkiMessage {
    fn from(message: PkiMessage) -> Self {
        Self { message }
    }
}

impl GeneralPkiMessage {
    pub fn decode(bytes: &[u8]) -> Result<Self, CmpError> {
        let (used, message) = PkiMessage::decode_der(bytes, &DecodingOptions::default())?;
        if used != bytes.len() {
            return Err(Asn1Error::TrailingData.into());
        }
        if message.encode_to_vec(&EncodingOptions::DER)? != bytes {
            return Err(CmpError::Invalid("noncanonical CMP DER"));
        }
        Ok(message.into())
    }

    pub fn encode(&self) -> Result<Vec<u8>, CmpError> {
        Ok(self.message.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn header(&self) -> &PkiHeader {
        self.message.header()
    }

    pub fn body(&self) -> &PkiBody {
        self.message.body()
    }

    pub fn has_protection(&self) -> bool {
        self.message.protection().is_some()
    }

    pub fn to_asn1(&self) -> &PkiMessage {
        &self.message
    }

    pub fn into_asn1(self) -> PkiMessage {
        self.message
    }
}
