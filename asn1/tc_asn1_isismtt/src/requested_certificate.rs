//! Common PKI `RequestedCertificate`, the value of the requestedCertificate OCSP
//! extension.
//!
//! ```text
//! RequestedCertificate ::= CHOICE {
//!     certificate          Certificate,
//!     publicKeyCertificate [0] EXPLICIT OCTET STRING,
//!     attributeCertificate [1] EXPLICIT OCTET STRING }
//! ```

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, tag,
};
use tc_asn1_x509::cert::Certificate;

/// The certificate itself, or the encoding of a public key or attribute certificate.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
// Keep every alternative inline as part of the public value API, without an extra allocation.
#[allow(clippy::large_enum_variant)]
pub enum RequestedCertificate {
    /// An X.509 certificate.
    Certificate(Certificate),
    /// `[0]`, an encoded public key certificate.
    PublicKeyCertificate(Asn1OctetString),
    /// `[1]`, an encoded attribute certificate.
    AttributeCertificate(Asn1OctetString),
}

impl DecodeInner for RequestedCertificate {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            tag::SEQUENCE => Self::Certificate(element.decode_as(context)?),
            [0xa0] => {
                let mut inner = element.children(context)?;
                let value = Self::PublicKeyCertificate(inner.get()?);
                inner.end()?;
                value
            }
            [0xa1] => {
                let mut inner = element.children(context)?;
                let value = Self::AttributeCertificate(inner.get()?);
                inner.end()?;
                value
            }
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for RequestedCertificate {}

impl EncodeContent for RequestedCertificate {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Certificate(inner) => inner.content_len(rules),
            Self::PublicKeyCertificate(inner) => inner.encoded_len(rules),
            Self::AttributeCertificate(inner) => inner.encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Certificate(inner) => inner.encode_content(rules, out),
            Self::PublicKeyCertificate(inner) => inner.encode(rules, out),
            Self::AttributeCertificate(inner) => inner.encode(rules, out),
        }
    }
}

impl EncodeTagged for RequestedCertificate {}

impl Encode for RequestedCertificate {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Certificate(inner) => inner.encoded_len(rules),
            Self::PublicKeyCertificate(inner) => Explicit::new(&[0xa0], inner).encoded_len(rules),
            Self::AttributeCertificate(inner) => Explicit::new(&[0xa1], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Certificate(inner) => inner.encode(rules, out),
            Self::PublicKeyCertificate(inner) => Explicit::new(&[0xa0], inner).encode(rules, out),
            Self::AttributeCertificate(inner) => Explicit::new(&[0xa1], inner).encode(rules, out),
        }
    }
}
