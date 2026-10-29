//! RFC 4210 §5.1 `CMPCertificate`, a certificate in a CMP message.
//!
//! ```text
//! CMPCertificate ::= CHOICE {
//!     x509v3PKCert Certificate,
//!     otherCert    [tag] EXPLICIT ANY DEFINED BY tag }
//! ```
//!
//! Bouncy Castle accepts any context-specific explicit tag for another
//! certificate format and keeps it as found; so does this type.

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, tag,
};
use tc_asn1_x509::cert::Certificate;

/// An X.509 certificate, or a certificate of another format under a context tag.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
// Keep every alternative inline as part of the public value API, without an extra allocation.
#[allow(clippy::large_enum_variant)]
pub enum CmpCertificate {
    /// An X.509 certificate.
    X509v3PkCert(Certificate),
    /// Another format, the whole `[n] EXPLICIT` element kept as found.
    OtherCert(Asn1Any),
}

impl DecodeInner for CmpCertificate {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            tag::SEQUENCE => Self::X509v3PkCert(element.decode_as(context)?),
            [tag] if tag & 0xe0 == 0xa0 => Self::OtherCert(element.decode_as(context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for CmpCertificate {}

impl EncodeContent for CmpCertificate {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::X509v3PkCert(inner) => inner.content_len(rules),
            Self::OtherCert(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::X509v3PkCert(inner) => inner.encode_content(rules, out),
            Self::OtherCert(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for CmpCertificate {}

impl Encode for CmpCertificate {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::X509v3PkCert(inner) => inner.encoded_len(rules),
            Self::OtherCert(inner) => inner.encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::X509v3PkCert(inner) => inner.encode(rules, out),
            Self::OtherCert(inner) => inner.encode(rules, out),
        }
    }
}
