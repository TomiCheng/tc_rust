//! RFC 4211 §4.1 `authInfo`, how a proof-of-possession input names its sender.
//!
//! ```text
//! authInfo CHOICE {
//!     sender       [0] GeneralName,
//!     publicKeyMAC PKMACValue }
//! ```
//!
//! `GeneralName` is a CHOICE, so its tag is explicit.

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Explicit, tag,
};
use tc_asn1_x509::name::GeneralName;

use crate::crmf::PkMacValue;

/// The sender's authenticated name, or a MAC over the public key.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum AuthInfo {
    /// `[0]`, a name from a currently valid certificate.
    Sender(GeneralName),
    /// A password-based MAC over the public key.
    PublicKeyMac(PkMacValue),
}

impl DecodeInner for AuthInfo {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0xa0] => {
                let mut inner = element.children(context)?;
                let value = Self::Sender(inner.get()?);
                inner.end()?;
                value
            }
            tag::SEQUENCE => Self::PublicKeyMac(element.decode_as(context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for AuthInfo {}

impl EncodeContent for AuthInfo {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Sender(inner) => inner.encoded_len(rules),
            Self::PublicKeyMac(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Sender(inner) => inner.encode(rules, out),
            Self::PublicKeyMac(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for AuthInfo {}

impl Encode for AuthInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Sender(inner) => Explicit::new(&[0xa0], inner).encoded_len(rules),
            Self::PublicKeyMac(inner) => inner.encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Sender(inner) => Explicit::new(&[0xa0], inner).encode(rules, out),
            Self::PublicKeyMac(inner) => inner.encode(rules, out),
        }
    }
}
