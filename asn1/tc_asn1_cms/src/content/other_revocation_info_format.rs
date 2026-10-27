//! RFC 5652 §10.2.1 `OtherRevocationInfoFormat`.
//!
//! ```text
//! OtherRevocationInfoFormat ::= SEQUENCE {
//!     otherRevInfoFormat OBJECT IDENTIFIER,
//!     otherRevInfo ANY DEFINED BY otherRevInfoFormat }
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, NamedOid, Tagged, tag,
};

/// Revocation information other than a CRL, such as an OCSP response, kept as
/// the octets it was read with.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtherRevocationInfoFormat {
    format: Asn1Oid,
    info: Asn1Any,
}

impl OtherRevocationInfoFormat {
    /// An OCSP response (RFC 5940), `id-ri-ocsp-response`.
    pub const OCSP_RESPONSE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x10, 0x02],
        "1.3.6.1.5.5.7.16.2",
        "id-ri-ocsp-response",
    );

    /// An SCVP response (RFC 5940), `id-ri-scvp`.
    pub const SCVP: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x10, 0x04],
        "1.3.6.1.5.5.7.16.4",
        "id-ri-scvp",
    );

    /// Stores the format identifier and the revocation information.
    /// Variable time: branches only on the encoding structure.
    pub fn new(format: Asn1Oid, info: Asn1Any) -> Self {
        Self { format, info }
    }

    /// Returns the format identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn format(&self) -> &Asn1Oid {
        &self.format
    }

    /// Returns the revocation information.
    /// Variable time: branches only on the encoding structure.
    pub fn info(&self) -> &Asn1Any {
        &self.info
    }
}

impl DecodeContent for OtherRevocationInfoFormat {
    /// The two fields, as under `30` on its own or `A1` in `RevocationInfoChoice`.
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let format = fields.get()?;
        let info = fields.get()?;
        fields.end()?;
        Ok(Self::new(format, info))
    }
}

impl DecodeInner for OtherRevocationInfoFormat {
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

impl EncodeContent for OtherRevocationInfoFormat {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.format.encoded_len(rules) + self.info.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.format.encode(rules, out)?;
        Ok(at + self.info.encode(rules, &mut out[at..])?)
    }
}

impl Decode for OtherRevocationInfoFormat {}

impl Tagged for OtherRevocationInfoFormat {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OtherRevocationInfoFormat {}

impl Encode for OtherRevocationInfoFormat {
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

    use super::OtherRevocationInfoFormat;

    #[test]
    fn the_revocation_format_identifiers_match_their_dotted_form() {
        for entry in [
            OtherRevocationInfoFormat::OCSP_RESPONSE,
            OtherRevocationInfoFormat::SCVP,
        ] {
            let oid: tc_asn1::Asn1Oid = entry.dotted().parse().unwrap();
            assert_eq!(entry.oid(), oid);
            assert_eq!(oid.to_string(), entry.dotted());
        }
    }
}
