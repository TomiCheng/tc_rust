//! RFC 4211 §4.2.1 `EncryptedKey`, an encrypted private key.
//!
//! ```text
//! EncryptedKey ::= CHOICE {
//!     encryptedValue    EncryptedValue,  -- Deprecated
//!     envelopedData [0] EnvelopedData }
//! ```
//!
//! The module uses implicit tags.

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Implicit, tag,
};
use tc_asn1_cms::content::EnvelopedData;

use crate::crmf::EncryptedValue;

/// The key in the deprecated `EncryptedValue` or in CMS `EnvelopedData`.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
// Keep every alternative inline as part of the public value API, without an extra allocation.
#[allow(clippy::large_enum_variant)]
pub enum EncryptedKey {
    /// Deprecated.
    EncryptedValue(EncryptedValue),
    /// `[0]`, the key in the encrypted content.
    EnvelopedData(EnvelopedData),
}

impl DecodeInner for EncryptedKey {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            tag::SEQUENCE => Self::EncryptedValue(element.decode_as(context)?),
            [0xa0] => Self::EnvelopedData(DecodeContent::decode_content(element.value(), context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for EncryptedKey {}

impl EncodeContent for EncryptedKey {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::EncryptedValue(inner) => inner.content_len(rules),
            Self::EnvelopedData(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::EncryptedValue(inner) => inner.encode_content(rules, out),
            Self::EnvelopedData(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for EncryptedKey {}

impl Encode for EncryptedKey {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::EncryptedValue(inner) => inner.encoded_len(rules),
            Self::EnvelopedData(inner) => Implicit::new(&[0xa0], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::EncryptedValue(inner) => inner.encode(rules, out),
            Self::EnvelopedData(inner) => Implicit::new(&[0xa0], inner).encode(rules, out),
        }
    }
}
