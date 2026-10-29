//! RFC 4211 §4.4 `EncKeyWithID`, a private key with a name, the content of
//! `id-ct-encKeyWithID`.
//!
//! ```text
//! EncKeyWithID ::= SEQUENCE {
//!     privateKey PrivateKeyInfo,
//!     identifier CHOICE {
//!         string      UTF8String,
//!         generalName GeneralName } OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_pkcs::PrivateKeyInfo;

use crate::crmf::EncKeyWithIdIdentifier;

/// A private key and, optionally, what identifies it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EncKeyWithId {
    private_key: PrivateKeyInfo,
    identifier: Option<EncKeyWithIdIdentifier>,
}

impl EncKeyWithId {
    /// The key, without an identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn new(private_key: PrivateKeyInfo) -> Self {
        Self {
            private_key,
            identifier: None,
        }
    }

    /// Sets the identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn with_identifier(mut self, identifier: EncKeyWithIdIdentifier) -> Self {
        self.identifier = Some(identifier);
        self
    }

    /// Returns the private key.
    /// Variable time: branches only on the encoding structure.
    pub fn private_key(&self) -> &PrivateKeyInfo {
        &self.private_key
    }

    /// Returns the identifier, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn identifier(&self) -> Option<&EncKeyWithIdIdentifier> {
        self.identifier.as_ref()
    }
}

impl DecodeContent for EncKeyWithId {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let private_key = fields.get()?;
        let identifier = fields.get_any_opt()?;
        fields.end()?;
        let value = Self {
            private_key,
            identifier,
        };
        Ok(value)
    }
}

impl DecodeInner for EncKeyWithId {
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

impl EncodeContent for EncKeyWithId {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.private_key.encoded_len(rules)
            + self.identifier.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.private_key.encode(rules, out)?;
        if let Some(v) = &self.identifier {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for EncKeyWithId {}

impl Tagged for EncKeyWithId {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EncKeyWithId {}

impl Encode for EncKeyWithId {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
