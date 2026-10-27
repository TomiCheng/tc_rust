//! RFC 5940 `SCVPReqRes`, an SCVP request and response carried as revocation
//! information of type [`OtherRevocationInfoFormat::SCVP`].
//!
//! ```text
//! SCVPReqRes ::= SEQUENCE {
//!     request  [0] EXPLICIT ContentInfo OPTIONAL,
//!     response     ContentInfo }
//! ```
//!
//! [`OtherRevocationInfoFormat::SCVP`]: crate::content::OtherRevocationInfoFormat::SCVP

use crate::content::ContentInfo;
use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

/// An SCVP response and, optionally, the request it answers.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ScvpReqRes {
    request: Option<ContentInfo>,
    response: ContentInfo,
}

impl ScvpReqRes {
    /// A response without its request.
    /// Variable time: branches only on the encoding structure.
    pub fn new(response: ContentInfo) -> Self {
        Self {
            request: None,
            response,
        }
    }

    /// Adds the request the response answers.
    /// Variable time: branches only on the encoding structure.
    pub fn with_request(mut self, request: ContentInfo) -> Self {
        self.request = Some(request);
        self
    }

    /// Returns the request, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn request(&self) -> Option<&ContentInfo> {
        self.request.as_ref()
    }

    /// Returns the response.
    /// Variable time: branches only on the encoding structure.
    pub fn response(&self) -> &ContentInfo {
        &self.response
    }
}

impl DecodeContent for ScvpReqRes {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let request = fields.get_explicit_opt::<ContentInfo>([0xa0])?;
        let response = fields.get()?;
        fields.end()?;
        let value = Self { request, response };
        Ok(value)
    }
}

impl DecodeInner for ScvpReqRes {
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

impl EncodeContent for ScvpReqRes {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.request
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self.response.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.request {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += self.response.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for ScvpReqRes {}

impl Tagged for ScvpReqRes {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ScvpReqRes {}

impl Encode for ScvpReqRes {
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
    use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};

    use super::ScvpReqRes;
    use crate::content::{ContentInfo, ContentType};

    #[test]
    fn the_request_is_explicitly_tagged_before_the_response() {
        let response = || ContentInfo::new(ContentType::SIGNED_DATA.oid());
        let bare = ScvpReqRes::new(response());
        let with_request = ScvpReqRes::new(response()).with_request(response());
        let wire = with_request.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire[2], 0xa0);
        for value in [bare, with_request] {
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                ScvpReqRes::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }
}
