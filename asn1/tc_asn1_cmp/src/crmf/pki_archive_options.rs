//! RFC 4211 §6.4 `PKIArchiveOptions`, the value of the pkiArchiveOptions control.
//!
//! ```text
//! PKIArchiveOptions ::= CHOICE {
//!     encryptedPrivKey     [0] EncryptedKey,
//!     keyGenParameters     [1] KeyGenParameters,
//!     archiveRemGenPrivKey [2] BOOLEAN }
//! KeyGenParameters ::= OCTET STRING
//! ```
//!
//! The module uses implicit tags; a CHOICE under a tag is still explicit.

use tc_asn1::{
    Asn1Boolean, Asn1Error, Asn1OctetString, Asn1Ref, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Implicit,
};

use crate::crmf::EncryptedKey;

/// What the CA should archive: an encrypted key, parameters to regenerate it,
/// or whether to archive a key it generates.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
// Keep every alternative inline as part of the public value API, without an extra allocation.
#[allow(clippy::large_enum_variant)]
pub enum PkiArchiveOptions {
    /// `[0]`, the private key itself, encrypted.
    EncryptedPrivKey(EncryptedKey),
    /// `[1]`, parameters to regenerate the key.
    KeyGenParameters(Asn1OctetString),
    /// `[2]`, whether to archive a key the CA generates.
    ArchiveRemGenPrivKey(Asn1Boolean),
}

impl DecodeInner for PkiArchiveOptions {
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
                let value = Self::EncryptedPrivKey(inner.get()?);
                inner.end()?;
                value
            }
            [0x81] => {
                Self::KeyGenParameters(DecodeContent::decode_content(element.value(), context)?)
            }
            [0x82] => {
                Self::ArchiveRemGenPrivKey(DecodeContent::decode_content(element.value(), context)?)
            }
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for PkiArchiveOptions {}

impl EncodeContent for PkiArchiveOptions {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::EncryptedPrivKey(inner) => inner.encoded_len(rules),
            Self::KeyGenParameters(inner) => inner.content_len(rules),
            Self::ArchiveRemGenPrivKey(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::EncryptedPrivKey(inner) => inner.encode(rules, out),
            Self::KeyGenParameters(inner) => inner.encode_content(rules, out),
            Self::ArchiveRemGenPrivKey(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for PkiArchiveOptions {}

impl Encode for PkiArchiveOptions {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::EncryptedPrivKey(inner) => Explicit::new(&[0xa0], inner).encoded_len(rules),
            Self::KeyGenParameters(inner) => Implicit::new(&[0x81], inner).encoded_len(rules),
            Self::ArchiveRemGenPrivKey(inner) => Implicit::new(&[0x82], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::EncryptedPrivKey(inner) => Explicit::new(&[0xa0], inner).encode(rules, out),
            Self::KeyGenParameters(inner) => Implicit::new(&[0x81], inner).encode(rules, out),
            Self::ArchiveRemGenPrivKey(inner) => Implicit::new(&[0x82], inner).encode(rules, out),
        }
    }
}
