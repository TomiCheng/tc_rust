//! RFC 5652 §6.2.5 `OtherRecipientInfo`, a recipient by another technique.
//!
//! ```text
//! OtherRecipientInfo ::= SEQUENCE {
//!     oriType OBJECT IDENTIFIER,
//!     oriValue ANY DEFINED BY oriType }
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, NamedOid, Tagged, tag,
};

/// A recipient type CMS itself does not define, kept as the octets it was read
/// with; a KEM recipient (RFC 9629) is one, with a [`KemRecipientInfo`] value.
///
/// [`KemRecipientInfo`]: crate::recipient::KemRecipientInfo
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtherRecipientInfo {
    ori_type: Asn1Oid,
    ori_value: Asn1Any,
}

impl OtherRecipientInfo {
    /// A KEM recipient (RFC 9629), `id-ori-kem`.
    pub const ID_ORI_KEM: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x0d, 0x03,
        ],
        "1.2.840.113549.1.9.16.13.3",
        "id-ori-kem",
    );

    /// Stores the recipient type and its value.
    /// Variable time: branches only on the encoding structure.
    pub fn new(ori_type: Asn1Oid, ori_value: Asn1Any) -> Self {
        Self {
            ori_type,
            ori_value,
        }
    }

    /// Returns the recipient type.
    /// Variable time: branches only on the encoding structure.
    pub fn ori_type(&self) -> &Asn1Oid {
        &self.ori_type
    }

    /// Returns the recipient value.
    /// Variable time: branches only on the encoding structure.
    pub fn ori_value(&self) -> &Asn1Any {
        &self.ori_value
    }
}

impl DecodeContent for OtherRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let ori_type = fields.get()?;
        let ori_value = fields.get()?;
        fields.end()?;
        let value = Self {
            ori_type,
            ori_value,
        };
        Ok(value)
    }
}

impl DecodeInner for OtherRecipientInfo {
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

impl EncodeContent for OtherRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.ori_type.encoded_len(rules) + self.ori_value.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.ori_type.encode(rules, out)?;
        at += self.ori_value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for OtherRecipientInfo {}

impl Tagged for OtherRecipientInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OtherRecipientInfo {}

impl Encode for OtherRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use tc_asn1::{Asn1Any, Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions, tag};

    use super::OtherRecipientInfo;

    #[test]
    fn the_kem_identifier_matches_its_dotted_form_and_values_round_trip() {
        let oid: Asn1Oid = OtherRecipientInfo::ID_ORI_KEM.dotted().parse().unwrap();
        assert_eq!(OtherRecipientInfo::ID_ORI_KEM.oid(), oid);
        assert_eq!(oid.to_string(), "1.2.840.113549.1.9.16.13.3");
        let value = OtherRecipientInfo::new(oid, Asn1Any::primitive(tag::OCTET_STRING, b"v"));
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            OtherRecipientInfo::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }
}
