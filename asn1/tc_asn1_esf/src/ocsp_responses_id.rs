//! RFC 5126 §5.7.4.1 `OcspResponsesID`, an OCSP response by identifier and hash.
//!
//! ```text
//! OcspResponsesID ::= SEQUENCE {
//!     ocspIdentifier OcspIdentifier,
//!     ocspRepHash    OtherHash OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::{OcspIdentifier, OtherHash};

/// An OCSP response and, optionally, its hash.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OcspResponsesId {
    ocsp_identifier: OcspIdentifier,
    ocsp_rep_hash: Option<OtherHash>,
}

impl OcspResponsesId {
    /// The response, without a hash.
    /// Variable time: branches only on the encoding structure.
    pub fn new(ocsp_identifier: OcspIdentifier) -> Self {
        Self {
            ocsp_identifier,
            ocsp_rep_hash: None,
        }
    }

    /// Sets the hash of the response.
    /// Variable time: branches only on the encoding structure.
    pub fn with_ocsp_rep_hash(mut self, ocsp_rep_hash: OtherHash) -> Self {
        self.ocsp_rep_hash = Some(ocsp_rep_hash);
        self
    }

    /// Returns the response's identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn ocsp_identifier(&self) -> &OcspIdentifier {
        &self.ocsp_identifier
    }

    /// Returns the hash of the response, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn ocsp_rep_hash(&self) -> Option<&OtherHash> {
        self.ocsp_rep_hash.as_ref()
    }
}

impl DecodeContent for OcspResponsesId {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let ocsp_identifier = fields.get()?;
        let ocsp_rep_hash = fields.get_any_opt()?;
        fields.end()?;
        let value = Self {
            ocsp_identifier,
            ocsp_rep_hash,
        };
        Ok(value)
    }
}

impl DecodeInner for OcspResponsesId {
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

impl EncodeContent for OcspResponsesId {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.ocsp_identifier.encoded_len(rules)
            + self
                .ocsp_rep_hash
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.ocsp_identifier.encode(rules, out)?;
        if let Some(v) = &self.ocsp_rep_hash {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for OcspResponsesId {}

impl Tagged for OcspResponsesId {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OcspResponsesId {}

impl Encode for OcspResponsesId {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
