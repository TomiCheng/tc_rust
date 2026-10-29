//! RFC 4211 §4.2 `POPOPrivKey`, a proof of possession of an encryption or
//! agreement key.
//!
//! ```text
//! POPOPrivKey ::= CHOICE {
//!     thisMessage       [0] BIT STRING,         -- Deprecated
//!     subsequentMessage [1] SubsequentMessage,
//!     dhMAC             [2] BIT STRING,         -- Deprecated
//!     agreeMAC          [3] PKMACValue,
//!     encryptedKey      [4] EnvelopedData }
//! ```
//!
//! The module uses implicit tags.

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Implicit,
};
use tc_asn1_cms::content::EnvelopedData;

use crate::crmf::{PkMacValue, SubsequentMessage};

/// How possession of the private key is or will be proven.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
// Keep every alternative inline as part of the public value API, without an extra allocation.
#[allow(clippy::large_enum_variant)]
pub enum PopoPrivKey {
    /// `[0]`, deprecated: the encrypted key in this message.
    ThisMessage(Asn1BitString),
    /// `[1]`, proven in a later message.
    SubsequentMessage(SubsequentMessage),
    /// `[2]`, deprecated: a Diffie-Hellman MAC.
    DhMac(Asn1BitString),
    /// `[3]`, a MAC under the agreed key.
    AgreeMac(PkMacValue),
    /// `[4]`, the key encrypted for the CA.
    EncryptedKey(EnvelopedData),
}

impl DecodeInner for PopoPrivKey {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0x80] => Self::ThisMessage(DecodeContent::decode_content(element.value(), context)?),
            [0x81] => {
                Self::SubsequentMessage(DecodeContent::decode_content(element.value(), context)?)
            }
            [0x82] => Self::DhMac(DecodeContent::decode_content(element.value(), context)?),
            [0xa3] => Self::AgreeMac(DecodeContent::decode_content(element.value(), context)?),
            [0xa4] => Self::EncryptedKey(DecodeContent::decode_content(element.value(), context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for PopoPrivKey {}

impl EncodeContent for PopoPrivKey {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::ThisMessage(inner) => inner.content_len(rules),
            Self::SubsequentMessage(inner) => inner.content_len(rules),
            Self::DhMac(inner) => inner.content_len(rules),
            Self::AgreeMac(inner) => inner.content_len(rules),
            Self::EncryptedKey(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::ThisMessage(inner) => inner.encode_content(rules, out),
            Self::SubsequentMessage(inner) => inner.encode_content(rules, out),
            Self::DhMac(inner) => inner.encode_content(rules, out),
            Self::AgreeMac(inner) => inner.encode_content(rules, out),
            Self::EncryptedKey(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for PopoPrivKey {}

impl Encode for PopoPrivKey {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::ThisMessage(inner) => Implicit::new(&[0x80], inner).encoded_len(rules),
            Self::SubsequentMessage(inner) => Implicit::new(&[0x81], inner).encoded_len(rules),
            Self::DhMac(inner) => Implicit::new(&[0x82], inner).encoded_len(rules),
            Self::AgreeMac(inner) => Implicit::new(&[0xa3], inner).encoded_len(rules),
            Self::EncryptedKey(inner) => Implicit::new(&[0xa4], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::ThisMessage(inner) => Implicit::new(&[0x80], inner).encode(rules, out),
            Self::SubsequentMessage(inner) => Implicit::new(&[0x81], inner).encode(rules, out),
            Self::DhMac(inner) => Implicit::new(&[0x82], inner).encode(rules, out),
            Self::AgreeMac(inner) => Implicit::new(&[0xa3], inner).encode(rules, out),
            Self::EncryptedKey(inner) => Implicit::new(&[0xa4], inner).encode(rules, out),
        }
    }
}
