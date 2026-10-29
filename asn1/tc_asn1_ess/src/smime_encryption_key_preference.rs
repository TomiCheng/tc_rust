//! RFC 8551 §2.5.3 `SMIMEEncryptionKeyPreference`, the value of the
//! encrypKeyPref attribute: which certificate to encrypt to.
//!
//! ```text
//! SMIMEEncryptionKeyPreference ::= CHOICE {
//!     issuerAndSerialNumber   [0] IssuerAndSerialNumber,
//!     receipentKeyId          [1] RecipientKeyIdentifier,
//!     subjectAltKeyIdentifier [2] SubjectKeyIdentifier }
//! ```
//!
//! The module uses implicit tags.

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Implicit,
};
use tc_asn1_cms::recipient::RecipientKeyIdentifier;
use tc_asn1_cms::signed::IssuerAndSerialNumber;
use tc_asn1_x509::ext::SubjectKeyIdentifier;

/// The certificate the sender prefers to be encrypted to.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SmimeEncryptionKeyPreference {
    /// `[0]`, by issuer and serial number.
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    /// `[1]`, by subject key identifier with an optional date.
    RecipientKeyId(RecipientKeyIdentifier),
    /// `[2]`, by a subject key identifier not in the signer's certificate.
    SubjectAltKeyIdentifier(SubjectKeyIdentifier),
}

impl SmimeEncryptionKeyPreference {
    fn tag(&self) -> &'static [u8] {
        match self {
            Self::IssuerAndSerialNumber(_) => &[0xa0],
            Self::RecipientKeyId(_) => &[0xa1],
            Self::SubjectAltKeyIdentifier(_) => &[0x82],
        }
    }

    fn inner(&self) -> &dyn Encode {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner,
            Self::RecipientKeyId(inner) => inner,
            Self::SubjectAltKeyIdentifier(inner) => inner,
        }
    }
}

impl DecodeInner for SmimeEncryptionKeyPreference {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = element.value();
        let preference = match element.tag() {
            [0xa0] => Self::IssuerAndSerialNumber(DecodeContent::decode_content(value, context)?),
            [0xa1] => Self::RecipientKeyId(DecodeContent::decode_content(value, context)?),
            [0x82] => Self::SubjectAltKeyIdentifier(DecodeContent::decode_content(value, context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), preference))
    }
}

impl Decode for SmimeEncryptionKeyPreference {}

impl EncodeContent for SmimeEncryptionKeyPreference {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.content_len(rules),
            Self::RecipientKeyId(inner) => inner.content_len(rules),
            Self::SubjectAltKeyIdentifier(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.encode_content(rules, out),
            Self::RecipientKeyId(inner) => inner.encode_content(rules, out),
            Self::SubjectAltKeyIdentifier(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for SmimeEncryptionKeyPreference {}

impl Encode for SmimeEncryptionKeyPreference {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        Implicit::new(self.tag(), self.inner()).encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        Implicit::new(self.tag(), self.inner()).encode(rules, out)
    }
}
