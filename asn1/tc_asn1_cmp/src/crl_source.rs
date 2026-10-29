//! RFC 9480 §2.17 `CRLSource`, where a CRL comes from.
//!
//! ```text
//! CRLSource ::= CHOICE {
//!     dpn    [0] DistributionPointName,
//!     issuer [1] GeneralNames }
//! ```
//!
//! The module uses explicit tags.

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Explicit,
};
use tc_asn1_x509::crl::DistributionPointName;
use tc_asn1_x509::name::GeneralNames;

/// A CRL by distribution point or by issuer.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum CrlSource {
    /// `[0]`, a distribution point name.
    Dpn(DistributionPointName),
    /// `[1]`, the CRL issuer.
    Issuer(GeneralNames),
}

impl DecodeInner for CrlSource {
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
                let value = Self::Dpn(inner.get()?);
                inner.end()?;
                value
            }
            [0xa1] => {
                let mut inner = element.children(context)?;
                let value = Self::Issuer(inner.get()?);
                inner.end()?;
                value
            }
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for CrlSource {}

impl EncodeContent for CrlSource {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Dpn(inner) => inner.encoded_len(rules),
            Self::Issuer(inner) => inner.encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Dpn(inner) => inner.encode(rules, out),
            Self::Issuer(inner) => inner.encode(rules, out),
        }
    }
}

impl EncodeTagged for CrlSource {}

impl Encode for CrlSource {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Dpn(inner) => Explicit::new(&[0xa0], inner).encoded_len(rules),
            Self::Issuer(inner) => Explicit::new(&[0xa1], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Dpn(inner) => Explicit::new(&[0xa0], inner).encode(rules, out),
            Self::Issuer(inner) => Explicit::new(&[0xa1], inner).encode(rules, out),
        }
    }
}
