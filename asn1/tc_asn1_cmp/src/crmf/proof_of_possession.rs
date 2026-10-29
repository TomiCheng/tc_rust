//! RFC 4211 §4 `ProofOfPossession`, proof that the requester holds the private key.
//!
//! ```text
//! ProofOfPossession ::= CHOICE {
//!     raVerified      [0] NULL,
//!     signature       [1] POPOSigningKey,
//!     keyEncipherment [2] POPOPrivKey,
//!     keyAgreement    [3] POPOPrivKey }
//! ```
//!
//! The module uses implicit tags; `POPOPrivKey` is a CHOICE, so `[2]` and `[3]`
//! are explicit.

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Explicit, Implicit,
};

use crate::crmf::{PopoPrivKey, PopoSigningKey};

/// Verified by an RA, a signature, or a proof for an encryption or agreement key.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
// Keep every alternative inline as part of the public value API, without an extra allocation.
#[allow(clippy::large_enum_variant)]
pub enum ProofOfPossession {
    /// `[0]`, an RA already verified possession.
    RaVerified,
    /// `[1]`, a signature with the key.
    Signature(PopoSigningKey),
    /// `[2]`, for an encryption key.
    KeyEncipherment(PopoPrivKey),
    /// `[3]`, for a key agreement key.
    KeyAgreement(PopoPrivKey),
}

impl DecodeInner for ProofOfPossession {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// A NULL alternative with contents is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0x80] if element.value().is_empty() => Self::RaVerified,
            [0x80] => return Err(Asn1Error::MalformedValue),
            [0xa1] => Self::Signature(DecodeContent::decode_content(element.value(), context)?),
            [0xa2] => {
                let mut inner = element.children(context)?;
                let value = Self::KeyEncipherment(inner.get()?);
                inner.end()?;
                value
            }
            [0xa3] => {
                let mut inner = element.children(context)?;
                let value = Self::KeyAgreement(inner.get()?);
                inner.end()?;
                value
            }
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for ProofOfPossession {}

impl EncodeContent for ProofOfPossession {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::RaVerified => 0,
            Self::Signature(inner) => inner.content_len(rules),
            Self::KeyEncipherment(inner) => inner.encoded_len(rules),
            Self::KeyAgreement(inner) => inner.encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::RaVerified => Ok(0),
            Self::Signature(inner) => inner.encode_content(rules, out),
            Self::KeyEncipherment(inner) => inner.encode(rules, out),
            Self::KeyAgreement(inner) => inner.encode(rules, out),
        }
    }
}

impl EncodeTagged for ProofOfPossession {}

impl Encode for ProofOfPossession {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::RaVerified => 2,
            Self::Signature(inner) => Implicit::new(&[0xa1], inner).encoded_len(rules),
            Self::KeyEncipherment(inner) => Explicit::new(&[0xa2], inner).encoded_len(rules),
            Self::KeyAgreement(inner) => Explicit::new(&[0xa3], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let null = |tag: u8, out: &mut [u8]| -> Result<usize, Asn1Error> {
            out.get_mut(..2)
                .ok_or(Asn1Error::BufferTooSmall)?
                .copy_from_slice(&[tag, 0]);
            Ok(2)
        };
        match self {
            Self::RaVerified => null(0x80, out),
            Self::Signature(inner) => Implicit::new(&[0xa1], inner).encode(rules, out),
            Self::KeyEncipherment(inner) => Explicit::new(&[0xa2], inner).encode(rules, out),
            Self::KeyAgreement(inner) => Explicit::new(&[0xa3], inner).encode(rules, out),
        }
    }
}
