//! RFC 6960 §4.2.1 `ResponseBytes`, a typed response in an OCTET STRING.
//!
//! ```text
//! ResponseBytes ::= SEQUENCE {
//!     responseType OBJECT IDENTIFIER,
//!     response     OCTET STRING }
//! ```

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The response type, such as `id-pkix-ocsp-basic`, and the encoded response.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ResponseBytes {
    response_type: Asn1Oid,
    response: Asn1OctetString,
}

impl ResponseBytes {
    /// The response type and the encoded response.
    /// Variable time: branches only on the encoding structure.
    pub fn new(response_type: Asn1Oid, response: Asn1OctetString) -> Self {
        Self {
            response_type,
            response,
        }
    }

    /// Returns the response type.
    /// Variable time: branches only on the encoding structure.
    pub fn response_type(&self) -> &Asn1Oid {
        &self.response_type
    }

    /// Returns the encoded response, a `BasicOCSPResponse` for `id-pkix-ocsp-basic`.
    /// Variable time: branches only on the encoding structure.
    pub fn response(&self) -> &Asn1OctetString {
        &self.response
    }
}

impl DecodeContent for ResponseBytes {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let response_type = fields.get()?;
        let response = fields.get()?;
        fields.end()?;
        let value = Self {
            response_type,
            response,
        };
        Ok(value)
    }
}

impl DecodeInner for ResponseBytes {
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

impl EncodeContent for ResponseBytes {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.response_type.encoded_len(rules) + self.response.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.response_type.encode(rules, out)?;
        at += self.response.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for ResponseBytes {}

impl Tagged for ResponseBytes {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ResponseBytes {}

impl Encode for ResponseBytes {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
