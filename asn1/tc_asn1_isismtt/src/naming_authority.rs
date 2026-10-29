//! Common PKI `NamingAuthority`, who names a profession.
//!
//! ```text
//! NamingAuthority ::= SEQUENCE {
//!     namingAuthorityID   OBJECT IDENTIFIER OPTIONAL,
//!     namingAuthorityUrl  IA5String OPTIONAL,
//!     namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ia5String, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x500::DirectoryString;

/// The naming authority by identifier, URL or text; any may be absent.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct NamingAuthority {
    naming_authority_id: Option<Asn1Oid>,
    naming_authority_url: Option<Asn1Ia5String>,
    naming_authority_text: Option<DirectoryString>,
}

impl NamingAuthority {
    /// An authority with every field absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new() -> Self {
        Self {
            naming_authority_id: None,
            naming_authority_url: None,
            naming_authority_text: None,
        }
    }

    /// Sets the identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn with_naming_authority_id(mut self, naming_authority_id: Asn1Oid) -> Self {
        self.naming_authority_id = Some(naming_authority_id);
        self
    }

    /// Sets the URL.
    /// Variable time: branches only on the encoding structure.
    pub fn with_naming_authority_url(mut self, naming_authority_url: Asn1Ia5String) -> Self {
        self.naming_authority_url = Some(naming_authority_url);
        self
    }

    /// Sets the text.
    /// Variable time: branches only on the encoding structure.
    pub fn with_naming_authority_text(mut self, naming_authority_text: DirectoryString) -> Self {
        self.naming_authority_text = Some(naming_authority_text);
        self
    }

    /// Returns the identifier, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn naming_authority_id(&self) -> Option<&Asn1Oid> {
        self.naming_authority_id.as_ref()
    }

    /// Returns the URL, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn naming_authority_url(&self) -> Option<&Asn1Ia5String> {
        self.naming_authority_url.as_ref()
    }

    /// Returns the text, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn naming_authority_text(&self) -> Option<&DirectoryString> {
        self.naming_authority_text.as_ref()
    }
}

impl DecodeContent for NamingAuthority {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let naming_authority_id = fields.get_opt()?;
        let naming_authority_url = fields.get_opt()?;
        let naming_authority_text = fields.get_any_opt()?;
        fields.end()?;
        let value = Self {
            naming_authority_id,
            naming_authority_url,
            naming_authority_text,
        };
        Ok(value)
    }
}

impl DecodeInner for NamingAuthority {
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

impl EncodeContent for NamingAuthority {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.naming_authority_id
            .as_ref()
            .map_or(0, |v| v.encoded_len(rules))
            + self
                .naming_authority_url
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
            + self
                .naming_authority_text
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.naming_authority_id {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.naming_authority_url {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.naming_authority_text {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for NamingAuthority {}

impl Tagged for NamingAuthority {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for NamingAuthority {}

impl Encode for NamingAuthority {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
