//! RFC 6960 §4.4.6 `ServiceLocator`, the value of the Service Locator
//! request extension: where to forward a request.
//!
//! ```text
//! ServiceLocator ::= SEQUENCE {
//!     issuer  Name,
//!     locator AuthorityInfoAccessSyntax OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x500::Name;
use tc_asn1_x509::ext::InformationAccess;

/// The certificate's issuer and its authority information access, if any.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ServiceLocator {
    issuer: Name,
    locator: Option<InformationAccess>,
}

impl ServiceLocator {
    /// The issuer, without a locator.
    /// Variable time: branches only on the encoding structure.
    pub fn new(issuer: Name) -> Self {
        Self {
            issuer,
            locator: None,
        }
    }

    /// Sets the certificate's authority information access.
    /// Variable time: branches only on the encoding structure.
    pub fn with_locator(mut self, locator: InformationAccess) -> Self {
        self.locator = Some(locator);
        self
    }

    /// Returns the issuer of the certificate asked about.
    /// Variable time: branches only on the encoding structure.
    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    /// Returns the certificate's authority information access, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn locator(&self) -> Option<&InformationAccess> {
        self.locator.as_ref()
    }
}

impl DecodeContent for ServiceLocator {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let issuer = fields.get()?;
        let locator = fields.get_opt()?;
        fields.end()?;
        let value = Self { issuer, locator };
        Ok(value)
    }
}

impl DecodeInner for ServiceLocator {
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

impl EncodeContent for ServiceLocator {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.issuer.encoded_len(rules) + self.locator.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.issuer.encode(rules, out)?;
        if let Some(v) = &self.locator {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for ServiceLocator {}

impl Tagged for ServiceLocator {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ServiceLocator {}

impl Encode for ServiceLocator {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
