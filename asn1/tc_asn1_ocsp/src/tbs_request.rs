//! RFC 6960 §4.1.1 `TBSRequest`, the signed part of an OCSP request.
//!
//! ```text
//! TBSRequest ::= SEQUENCE {
//!     version           [0] EXPLICIT Version DEFAULT v1,
//!     requestorName     [1] EXPLICIT GeneralName OPTIONAL,
//!     requestList           SEQUENCE OF Request,
//!     requestExtensions [2] EXPLICIT Extensions OPTIONAL }
//! ```
//!
//! A version written as its default v1 is kept and written back, as Bouncy
//! Castle does, so a signature over the encoding still verifies.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::ext::Extensions;
use tc_asn1_x509::name::GeneralName;

use crate::Request;

/// The requests, who asks, and extensions such as a nonce.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TbsRequest {
    version: Option<Asn1Integer>,
    requestor_name: Option<GeneralName>,
    request_list: Asn1SequenceOf<Request>,
    request_extensions: Option<Extensions>,
}

impl TbsRequest {
    /// The requests, as version 1 without a requestor name or extensions.
    /// Variable time: branches only on the encoding structure.
    pub fn new(request_list: Vec<Request>) -> Self {
        Self {
            version: None,
            requestor_name: None,
            request_list: Asn1SequenceOf::new(request_list),
            request_extensions: None,
        }
    }

    /// Writes the version, even v1 (0), which is otherwise omitted.
    /// Variable time: branches only on the encoding structure.
    pub fn with_version(mut self, version: Asn1Integer) -> Self {
        self.version = Some(version);
        self
    }

    /// Sets the requestor's name, which a signed request must carry.
    /// Variable time: branches only on the encoding structure.
    pub fn with_requestor_name(mut self, requestor_name: GeneralName) -> Self {
        self.requestor_name = Some(requestor_name);
        self
    }

    /// Sets the extensions of the whole request, such as a nonce.
    /// Variable time: branches only on the encoding structure.
    pub fn with_request_extensions(mut self, request_extensions: Extensions) -> Self {
        self.request_extensions = Some(request_extensions);
        self
    }

    /// Returns the version, v1 (0) when absent.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version.clone().unwrap_or_else(|| 0.into())
    }

    /// Returns the requestor's name, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn requestor_name(&self) -> Option<&GeneralName> {
        self.requestor_name.as_ref()
    }

    /// Returns the requests in order.
    /// Variable time: branches only on the encoding structure.
    pub fn request_list(&self) -> &[Request] {
        self.request_list.elements()
    }

    /// Returns the extensions of the whole request, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn request_extensions(&self) -> Option<&Extensions> {
        self.request_extensions.as_ref()
    }
}

impl DecodeContent for TbsRequest {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version = fields.get_explicit_opt::<Asn1Integer>([0xa0])?;
        let requestor_name = fields.get_explicit_opt::<GeneralName>([0xa1])?;
        let request_list = fields.get()?;
        let request_extensions = fields.get_explicit_opt::<Extensions>([0xa2])?;
        fields.end()?;
        let value = Self {
            version,
            requestor_name,
            request_list,
            request_extensions,
        };
        Ok(value)
    }
}

impl DecodeInner for TbsRequest {
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

impl EncodeContent for TbsRequest {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .requestor_name
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self.request_list.encoded_len(rules)
            + self
                .request_extensions
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa2], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.version {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.requestor_name {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        at += self.request_list.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.request_extensions {
            at += Explicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for TbsRequest {}

impl Tagged for TbsRequest {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for TbsRequest {}

impl Encode for TbsRequest {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
