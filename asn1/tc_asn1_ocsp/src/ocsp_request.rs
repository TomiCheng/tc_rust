//! RFC 6960 §4.1.1 `OCSPRequest`.
//!
//! ```text
//! OCSPRequest ::= SEQUENCE {
//!     tbsRequest        TBSRequest,
//!     optionalSignature [0] EXPLICIT Signature OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

use crate::{Signature, TbsRequest};

/// An OCSP request, signed or not.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OcspRequest {
    tbs_request: TbsRequest,
    optional_signature: Option<Signature>,
}

impl OcspRequest {
    /// An unsigned request.
    /// Variable time: branches only on the encoding structure.
    pub fn new(tbs_request: TbsRequest) -> Self {
        Self {
            tbs_request,
            optional_signature: None,
        }
    }

    /// Sets the signature over the encoded `TBSRequest`.
    /// Variable time: branches only on the encoding structure.
    pub fn with_optional_signature(mut self, optional_signature: Signature) -> Self {
        self.optional_signature = Some(optional_signature);
        self
    }

    /// Returns the signed part.
    /// Variable time: branches only on the encoding structure.
    pub fn tbs_request(&self) -> &TbsRequest {
        &self.tbs_request
    }

    /// Returns the signature, if the request is signed.
    /// Variable time: branches only on the encoding structure.
    pub fn optional_signature(&self) -> Option<&Signature> {
        self.optional_signature.as_ref()
    }
}

impl DecodeContent for OcspRequest {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let tbs_request = fields.get()?;
        let optional_signature = fields.get_explicit_opt::<Signature>([0xa0])?;
        fields.end()?;
        let value = Self {
            tbs_request,
            optional_signature,
        };
        Ok(value)
    }
}

impl DecodeInner for OcspRequest {
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

impl EncodeContent for OcspRequest {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.tbs_request.encoded_len(rules)
            + self
                .optional_signature
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.tbs_request.encode(rules, out)?;
        if let Some(v) = &self.optional_signature {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for OcspRequest {}

impl Tagged for OcspRequest {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OcspRequest {}

impl Encode for OcspRequest {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
