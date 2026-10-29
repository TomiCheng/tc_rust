//! RFC 4211 §6.3 `SinglePubInfo`, where to publish a certificate.
//!
//! ```text
//! SinglePubInfo ::= SEQUENCE {
//!     pubMethod   INTEGER { dontCare (0), x500 (1), web (2), ldap (3) },
//!     pubLocation GeneralName OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::name::GeneralName;

/// A publication method and, optionally, where.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SinglePubInfo {
    pub_method: Asn1Integer,
    pub_location: Option<GeneralName>,
}

impl SinglePubInfo {
    /// A method without a location.
    /// Variable time: branches only on the encoding structure.
    pub fn new(pub_method: Asn1Integer) -> Self {
        Self {
            pub_method,
            pub_location: None,
        }
    }

    /// Sets the location.
    /// Variable time: branches only on the encoding structure.
    pub fn with_pub_location(mut self, pub_location: GeneralName) -> Self {
        self.pub_location = Some(pub_location);
        self
    }

    /// Returns the method: 0 dontCare, 1 x500, 2 web, 3 ldap.
    /// Variable time: branches only on the encoding structure.
    pub fn pub_method(&self) -> &Asn1Integer {
        &self.pub_method
    }

    /// Returns the location, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn pub_location(&self) -> Option<&GeneralName> {
        self.pub_location.as_ref()
    }
}

impl DecodeContent for SinglePubInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let pub_method = fields.get()?;
        let pub_location = fields.get_any_opt()?;
        fields.end()?;
        let value = Self {
            pub_method,
            pub_location,
        };
        Ok(value)
    }
}

impl DecodeInner for SinglePubInfo {
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

impl EncodeContent for SinglePubInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.pub_method.encoded_len(rules)
            + self
                .pub_location
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.pub_method.encode(rules, out)?;
        if let Some(v) = &self.pub_location {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for SinglePubInfo {}

impl Tagged for SinglePubInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SinglePubInfo {}

impl Encode for SinglePubInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
