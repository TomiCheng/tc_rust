//! RFC 4998 §2.1 `EncryptionInfo`, how archived data was encrypted.
//!
//! ```text
//! EncryptionInfo ::= SEQUENCE {
//!     encryptionInfoType  OBJECT IDENTIFIER,
//!     encryptionInfoValue ANY DEFINED BY encryptionInfoType }
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The type of the encryption information and its value, kept as found.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EncryptionInfo {
    encryption_info_type: Asn1Oid,
    encryption_info_value: Asn1Any,
}

impl EncryptionInfo {
    /// The type and its value.
    /// Variable time: branches only on the encoding structure.
    pub fn new(encryption_info_type: Asn1Oid, encryption_info_value: Asn1Any) -> Self {
        Self {
            encryption_info_type,
            encryption_info_value,
        }
    }

    /// Returns the type of the value.
    /// Variable time: branches only on the encoding structure.
    pub fn encryption_info_type(&self) -> &Asn1Oid {
        &self.encryption_info_type
    }

    /// Returns the value.
    /// Variable time: branches only on the encoding structure.
    pub fn encryption_info_value(&self) -> &Asn1Any {
        &self.encryption_info_value
    }
}

impl DecodeContent for EncryptionInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let encryption_info_type = fields.get()?;
        let encryption_info_value = fields.get()?;
        fields.end()?;
        let value = Self {
            encryption_info_type,
            encryption_info_value,
        };
        Ok(value)
    }
}

impl DecodeInner for EncryptionInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for EncryptionInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.encryption_info_type.encoded_len(rules) + self.encryption_info_value.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.encryption_info_type.encode(rules, out)?;
        at += self.encryption_info_value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for EncryptionInfo {}

impl Tagged for EncryptionInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EncryptionInfo {}

impl Encode for EncryptionInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
