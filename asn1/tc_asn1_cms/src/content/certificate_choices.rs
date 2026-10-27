//! RFC 5652 §10.2.2 `CertificateChoices`, a member of the certificate sets in
//! `SignedData` and `OriginatorInfo`.
//!
//! ```text
//! CertificateChoices ::= CHOICE {
//!     certificate Certificate,
//!     extendedCertificate [0] IMPLICIT ExtendedCertificate,   -- Obsolete
//!     v1AttrCert [1] IMPLICIT AttributeCertificateV1,         -- Obsolete
//!     v2AttrCert [2] IMPLICIT AttributeCertificateV2,
//!     other [3] IMPLICIT OtherCertificateFormat }
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Implicit,
};
use tc_asn1_x509::attr::AttributeCertificate;
use tc_asn1_x509::cert::Certificate;

use crate::content::OtherCertificateFormat;

/// One certificate in a CMS certificate set.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
/// The two obsolete alternatives are kept as the octets they were read with.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum CertificateChoices {
    /// An X.509 certificate.
    Certificate(Certificate),
    /// `[0]`, a PKCS #6 extended certificate, kept whole with its tag.
    ExtendedCertificate(Asn1Any),
    /// `[1]`, a version 1 attribute certificate, kept whole with its tag.
    V1AttrCert(Asn1Any),
    /// `[2]`, a version 2 attribute certificate.
    V2AttrCert(AttributeCertificate),
    /// `[3]`, a certificate in another format.
    Other(OtherCertificateFormat),
}

impl From<Certificate> for CertificateChoices {
    /// Variable time: branches only on the encoding structure.
    fn from(value: Certificate) -> Self {
        Self::Certificate(value)
    }
}

impl From<AttributeCertificate> for CertificateChoices {
    /// Variable time: branches only on the encoding structure.
    fn from(value: AttributeCertificate) -> Self {
        Self::V2AttrCert(value)
    }
}

impl DecodeInner for CertificateChoices {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0x30] => Self::Certificate(element.decode_as(context)?),
            [0xa0] => Self::ExtendedCertificate(element.decode_as(context)?),
            [0xa1] => Self::V1AttrCert(element.decode_as(context)?),
            [0xa2] => Self::V2AttrCert(AttributeCertificate::decode_content(
                element.value(),
                context,
            )?),
            [0xa3] => Self::Other(OtherCertificateFormat::decode_content(
                element.value(),
                context,
            )?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for CertificateChoices {}

impl EncodeContent for CertificateChoices {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Certificate(inner) => inner.content_len(rules),
            Self::ExtendedCertificate(inner) | Self::V1AttrCert(inner) => inner.content_len(rules),
            Self::V2AttrCert(inner) => inner.content_len(rules),
            Self::Other(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Certificate(inner) => inner.encode_content(rules, out),
            Self::ExtendedCertificate(inner) | Self::V1AttrCert(inner) => {
                inner.encode_content(rules, out)
            }
            Self::V2AttrCert(inner) => inner.encode_content(rules, out),
            Self::Other(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for CertificateChoices {}

impl Encode for CertificateChoices {
    /// The whole alternative; the obsolete ones are written back as read.
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Certificate(inner) => inner.encoded_len(rules),
            Self::ExtendedCertificate(inner) | Self::V1AttrCert(inner) => inner.encoded_len(rules),
            Self::V2AttrCert(inner) => Implicit::new(&[0xa2], inner).encoded_len(rules),
            Self::Other(inner) => Implicit::new(&[0xa3], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Certificate(inner) => inner.encode(rules, out),
            Self::ExtendedCertificate(inner) | Self::V1AttrCert(inner) => inner.encode(rules, out),
            Self::V2AttrCert(inner) => Implicit::new(&[0xa2], inner).encode(rules, out),
            Self::Other(inner) => Implicit::new(&[0xa3], inner).encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use tc_asn1::{
        Asn1Any, Asn1BitString, Asn1Error, Asn1GeneralizedTime, Asn1Oid, Decode, DecodingOptions,
        Encode, EncodingOptions, tag,
    };
    use tc_asn1_x500::{Attribute, DirectoryString};
    use tc_asn1_x509::alg::AlgorithmIdentifier;
    use tc_asn1_x509::attr::{
        AttCertValidityPeriod, AttributeCertificate, AttributeCertificateInfo, Holder, V2Form,
    };
    use tc_asn1_x509::cert::Certificate;
    use tc_asn1_x509::name::{GeneralName, GeneralNames};

    use super::CertificateChoices;
    use crate::content::OtherCertificateFormat;

    const RFC_8410: &[u8] = include_bytes!("../../tests/data/rfc8410.der");

    fn attribute_certificate() -> AttributeCertificate {
        let names = GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap();
        let start = Asn1GeneralizedTime::new(2026, 1, 1, 0, 0, 0).unwrap();
        let end = Asn1GeneralizedTime::new(2027, 1, 1, 0, 0, 0).unwrap();
        let info = AttributeCertificateInfo::new(
            Holder::new(None, Some(names.clone()), None).unwrap(),
            V2Form::new(Some(names), None, None).unwrap().into(),
            AlgorithmIdentifier::new("1.2.3".parse().unwrap()),
            1.into(),
            AttCertValidityPeriod::new(start, end).unwrap(),
            vec![
                Attribute::new(
                    "1.2.3".parse::<Asn1Oid>().unwrap(),
                    vec![DirectoryString::new("x").unwrap().into()],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        AttributeCertificate::new(info, Asn1BitString::from_bytes(&[0xaa])).unwrap()
    }

    fn round_trip(value: &CertificateChoices) -> alloc::vec::Vec<u8> {
        let wire = value.encode_to_vec(&EncodingOptions::BER).unwrap();
        let (used, back) = CertificateChoices::decode(&wire, &DecodingOptions::default()).unwrap();
        assert_eq!((used, &back), (wire.len(), value));
        wire
    }

    #[test]
    fn an_x509_certificate_is_the_untagged_alternative_and_keeps_its_octets() {
        let certificate = Certificate::decode(RFC_8410, &DecodingOptions::default())
            .unwrap()
            .1;
        let value = CertificateChoices::from(certificate);
        assert_eq!(round_trip(&value), RFC_8410);
    }

    #[test]
    fn a_v2_attribute_certificate_replaces_its_sequence_tag_with_context_two() {
        let attribute = attribute_certificate();
        let plain = attribute.encode_to_vec(&EncodingOptions::DER).unwrap();
        let wire = round_trip(&CertificateChoices::from(attribute));
        assert_eq!(wire[0], 0xa2);
        assert_eq!(wire[1..], plain[1..]);
    }

    #[test]
    fn other_formats_and_the_obsolete_alternatives_round_trip() {
        let other = CertificateChoices::Other(OtherCertificateFormat::new(
            "1.2.3.4".parse().unwrap(),
            Asn1Any::primitive(tag::OCTET_STRING, b"cert"),
        ));
        assert_eq!(round_trip(&other)[0], 0xa3);
        for (wire, obsolete) in [
            (&b"\xa0\x02\x05\x00"[..], true),
            (&b"\xa1\x02\x05\x00"[..], false),
        ] {
            let value = CertificateChoices::decode(wire, &DecodingOptions::default())
                .unwrap()
                .1;
            assert_eq!(
                matches!(value, CertificateChoices::ExtendedCertificate(_)),
                obsolete
            );
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        }
    }

    #[test]
    fn identifiers_outside_the_choice_are_rejected() {
        for wire in [&b"\x04\x00"[..], &b"\xa4\x00"[..], &b"\x82\x00"[..]] {
            assert_eq!(
                CertificateChoices::decode(wire, &DecodingOptions::default()),
                Err(Asn1Error::UnexpectedTag)
            );
        }
    }
}
