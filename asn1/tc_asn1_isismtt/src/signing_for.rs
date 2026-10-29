//! Common PKI `SigningFor`, on whose behalf a procuration signs.
//!
//! ```text
//! SigningFor ::= CHOICE {
//!     thirdPerson GeneralName,
//!     certRef     IssuerSerial }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, tag,
};
use tc_asn1_x509::attr::IssuerSerial;
use tc_asn1_x509::name::GeneralName;

/// A third person by name, or by the issuer and serial of their certificate.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SigningFor {
    /// The third person's certificate.
    CertRef(IssuerSerial),
    /// The third person's name.
    ThirdPerson(GeneralName),
}

impl DecodeInner for SigningFor {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            tag::SEQUENCE => Self::CertRef(element.decode_as(context)?),
            _ => Self::ThirdPerson(element.decode_as(context)?),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for SigningFor {}

impl EncodeContent for SigningFor {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::CertRef(inner) => inner.content_len(rules),
            Self::ThirdPerson(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::CertRef(inner) => inner.encode_content(rules, out),
            Self::ThirdPerson(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for SigningFor {}

impl Encode for SigningFor {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::CertRef(inner) => inner.encoded_len(rules),
            Self::ThirdPerson(inner) => inner.encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::CertRef(inner) => inner.encode(rules, out),
            Self::ThirdPerson(inner) => inner.encode(rules, out),
        }
    }
}
