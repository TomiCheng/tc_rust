//! RFC 7292 §4 `PFX`, the outer structure of a PKCS #12 file.
//!
//! ```text
//! PFX ::= SEQUENCE {
//!     version  INTEGER {v3(3)}(v3,...),
//!     authSafe ContentInfo,
//!     macData  MacData OPTIONAL }
//! ```
//!
//! As in Bouncy Castle, a version other than 3 is rejected.

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_cms::content::ContentInfo;

use crate::MacData;

/// The authenticated safe, data or signed data holding an `AuthenticatedSafe`,
/// and the MAC over it in password integrity mode.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Pfx {
    version: Option<Asn1Integer>,
    auth_safe: ContentInfo,
    mac_data: Option<MacData>,
}

impl Pfx {
    /// The authenticated safe, without a MAC, as in public-key integrity mode.
    /// Variable time: branches only on the encoding structure.
    pub fn new(auth_safe: ContentInfo) -> Self {
        Self {
            version: None,
            auth_safe,
            mac_data: None,
        }
    }

    /// Adds the MAC data of password integrity mode.
    /// Variable time: branches only on the encoding structure.
    pub fn with_mac_data(mut self, mac_data: MacData) -> Self {
        self.mac_data = Some(mac_data);
        self
    }

    /// Returns the decoded version, or the one RFC 7292 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// Always 3.
    fn derived_version(&self) -> Asn1Integer {
        3.into()
    }

    /// Returns the authenticated safe.
    /// Variable time: branches only on the encoding structure.
    pub fn auth_safe(&self) -> &ContentInfo {
        &self.auth_safe
    }

    /// Returns the MAC data, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn mac_data(&self) -> Option<&MacData> {
        self.mac_data.as_ref()
    }
}

impl DecodeContent for Pfx {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let auth_safe = fields.get()?;
        let mac_data = fields.get_opt()?;
        fields.end()?;
        if version != Asn1Integer::from(3) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            version: None,
            auth_safe,
            mac_data,
        })
    }
}

impl DecodeInner for Pfx {
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

impl EncodeContent for Pfx {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.auth_safe.encoded_len(rules)
            + self.mac_data.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.auth_safe.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.mac_data {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for Pfx {}

impl Tagged for Pfx {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Pfx {}

impl Encode for Pfx {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
