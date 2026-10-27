//! RFC 5652 §10.2.1 `RevocationInfoChoice`, a member of the revocation sets in
//! `SignedData` and `OriginatorInfo`.
//!
//! ```text
//! RevocationInfoChoice ::= CHOICE {
//!     crl CertificateList,
//!     other [1] IMPLICIT OtherRevocationInfoFormat }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Implicit,
};
use tc_asn1_x509::crl::CertificateList;

use crate::content::OtherRevocationInfoFormat;

/// One piece of revocation information: a CRL or another format.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
// Keep the CRL inline as part of the public value API, without an extra allocation.
#[allow(clippy::large_enum_variant)]
pub enum RevocationInfoChoice {
    /// An X.509 CRL.
    Crl(CertificateList),
    /// `[1]`, revocation information in another format, such as an OCSP response.
    Other(OtherRevocationInfoFormat),
}

impl From<CertificateList> for RevocationInfoChoice {
    /// Variable time: branches only on the encoding structure.
    fn from(value: CertificateList) -> Self {
        Self::Crl(value)
    }
}

impl From<OtherRevocationInfoFormat> for RevocationInfoChoice {
    /// Variable time: branches only on the encoding structure.
    fn from(value: OtherRevocationInfoFormat) -> Self {
        Self::Other(value)
    }
}

impl DecodeInner for RevocationInfoChoice {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0x30] => Self::Crl(element.decode_as(context)?),
            [0xa1] => Self::Other(OtherRevocationInfoFormat::decode_content(
                element.value(),
                context,
            )?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for RevocationInfoChoice {}

impl EncodeContent for RevocationInfoChoice {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Crl(inner) => inner.content_len(rules),
            Self::Other(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Crl(inner) => inner.encode_content(rules, out),
            Self::Other(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for RevocationInfoChoice {}

impl Encode for RevocationInfoChoice {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Crl(inner) => inner.encoded_len(rules),
            Self::Other(inner) => Implicit::new(&[0xa1], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Crl(inner) => inner.encode(rules, out),
            Self::Other(inner) => Implicit::new(&[0xa1], inner).encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Any, Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions, tag};

    use super::RevocationInfoChoice;
    use crate::content::OtherRevocationInfoFormat;
    use crate::fixtures::{CRL, crl};

    #[test]
    fn a_crl_is_the_untagged_alternative() {
        let value = RevocationInfoChoice::from(crl());
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), CRL);
        assert_eq!(
            RevocationInfoChoice::decode_der(CRL, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn an_ocsp_response_goes_under_an_implicit_context_one() {
        let value = RevocationInfoChoice::from(OtherRevocationInfoFormat::new(
            OtherRevocationInfoFormat::OCSP_RESPONSE.oid(),
            Asn1Any::primitive(tag::OCTET_STRING, b"resp"),
        ));
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire[0], 0xa1);
        assert_eq!(
            RevocationInfoChoice::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn identifiers_outside_the_choice_are_rejected() {
        for wire in [&b"\xa0\x00"[..], &b"\x31\x00"[..]] {
            assert_eq!(
                RevocationInfoChoice::decode(wire, &DecodingOptions::default()),
                Err(Asn1Error::UnexpectedTag)
            );
        }
    }
}
