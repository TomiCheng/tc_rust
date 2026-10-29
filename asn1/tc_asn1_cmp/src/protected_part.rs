//! RFC 4210 §5.1.3 `ProtectedPart`, what the protection of a message covers.
//!
//! ```text
//! ProtectedPart ::= SEQUENCE {
//!     header PKIHeader,
//!     body   PKIBody }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::{PkiBody, PkiHeader};

/// The header and body, encoded to compute or check the protection.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProtectedPart {
    header: PkiHeader,
    body: PkiBody,
}

impl ProtectedPart {
    /// The header and body.
    /// Variable time: branches only on the encoding structure.
    pub fn new(header: PkiHeader, body: PkiBody) -> Self {
        Self { header, body }
    }

    /// Returns the header.
    /// Variable time: branches only on the encoding structure.
    pub fn header(&self) -> &PkiHeader {
        &self.header
    }

    /// Returns the body.
    /// Variable time: branches only on the encoding structure.
    pub fn body(&self) -> &PkiBody {
        &self.body
    }
}

impl DecodeContent for ProtectedPart {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let header = fields.get()?;
        let body = fields.get()?;
        fields.end()?;
        let value = Self { header, body };
        Ok(value)
    }
}

impl DecodeInner for ProtectedPart {
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

impl EncodeContent for ProtectedPart {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.header.encoded_len(rules) + self.body.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.header.encode(rules, out)?;
        at += self.body.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for ProtectedPart {}

impl Tagged for ProtectedPart {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ProtectedPart {}

impl Encode for ProtectedPart {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
