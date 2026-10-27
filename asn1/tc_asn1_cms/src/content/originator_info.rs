//! RFC 5652 §6.1 `OriginatorInfo`, the certificates and revocation information
//! an enveloped message carries for its recipients.
//!
//! ```text
//! OriginatorInfo ::= SEQUENCE {
//!     certs [0] IMPLICIT CertificateSet OPTIONAL,
//!     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
//! CertificateSet ::= SET OF CertificateChoices
//! RevocationInfoChoices ::= SET OF RevocationInfoChoice
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SetOf, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};

use crate::content::{CertificateChoices, RevocationInfoChoice};

/// Certificates and revocation information for the recipients of an enveloped
/// message.
///
/// A set that is present may be empty; absent and empty are kept apart. Under
/// CER and DER the members are sorted on output, as X.690 requires of a SET OF.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::content::OriginatorInfo;
///
/// let info = OriginatorInfo::new().with_certificates(Vec::new());
/// let der = info.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x30, 0x02, 0xa0, 0x00]);
/// assert_eq!(OriginatorInfo::decode_der(&der, &DecodingOptions::default())?.1, info);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct OriginatorInfo {
    certificates: Option<Asn1SetOf<CertificateChoices>>,
    crls: Option<Asn1SetOf<RevocationInfoChoice>>,
}

impl OriginatorInfo {
    /// Neither certificates nor revocation information.
    /// Variable time: branches only on the encoding structure.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the certificate set, which may be empty.
    /// Variable time: branches only on the encoding structure.
    pub fn with_certificates(mut self, certificates: Vec<CertificateChoices>) -> Self {
        self.certificates = Some(Asn1SetOf::new(certificates));
        self
    }

    /// Sets the revocation information set, which may be empty.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crls(mut self, crls: Vec<RevocationInfoChoice>) -> Self {
        self.crls = Some(Asn1SetOf::new(crls));
        self
    }

    /// Returns the certificates in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn certificates(&self) -> Option<&[CertificateChoices]> {
        self.certificates.as_ref().map(Asn1SetOf::members)
    }

    /// Returns the revocation information in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crls(&self) -> Option<&[RevocationInfoChoice]> {
        self.crls.as_ref().map(Asn1SetOf::members)
    }

    /// Whether any certificate or revocation information is in another format,
    /// the first test of the version rules of RFC 5652 §6.1 and §9.1.
    pub(crate) fn has_other_formats(&self) -> bool {
        self.certificates()
            .unwrap_or_default()
            .iter()
            .any(|c| matches!(c, CertificateChoices::Other(_)))
            || self
                .crls()
                .unwrap_or_default()
                .iter()
                .any(|c| matches!(c, RevocationInfoChoice::Other(_)))
    }

    /// Whether any certificate is a version 2 attribute certificate.
    pub(crate) fn has_v2_attribute_certificates(&self) -> bool {
        self.certificates()
            .unwrap_or_default()
            .iter()
            .any(|c| matches!(c, CertificateChoices::V2AttrCert(_)))
    }
}

impl DecodeContent for OriginatorInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let certificates = fields.get_implicit_opt([0xa0])?;
        let crls = fields.get_implicit_opt([0xa1])?;
        fields.end()?;
        Ok(Self { certificates, crls })
    }
}

impl DecodeInner for OriginatorInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for OriginatorInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.certificates
            .as_ref()
            .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .crls
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa1], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.certificates {
            at += Implicit::new(&[0xa0], v).encode(rules, out)?;
        }
        if let Some(v) = &self.crls {
            at += Implicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for OriginatorInfo {}

impl Tagged for OriginatorInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OriginatorInfo {}

impl Encode for OriginatorInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x509::cert::Certificate;

    use super::OriginatorInfo;
    use crate::content::{CertificateChoices, RevocationInfoChoice};
    use crate::fixtures::{CRL, RFC_8410, crl};

    #[test]
    fn an_empty_originator_info_is_an_empty_sequence() {
        let value = OriginatorInfo::new();
        assert_eq!(
            value.encode_to_vec(&EncodingOptions::DER).unwrap(),
            [0x30, 0x00]
        );
        assert_eq!(value.certificates(), None);
        assert_eq!(value.crls(), None);
    }

    #[test]
    fn certificates_and_crls_go_under_implicit_zero_and_one() {
        let certificate = Certificate::decode(RFC_8410, &DecodingOptions::default())
            .unwrap()
            .1;
        let value = OriginatorInfo::new()
            .with_certificates(vec![CertificateChoices::from(certificate)])
            .with_crls(vec![RevocationInfoChoice::from(crl())]);
        let wire = value.encode_to_vec(&EncodingOptions::BER).unwrap();
        let certs_len = RFC_8410.len();
        // 30 82 LL LL | A0 82 LL LL <certificate> | A1 27 <crl>
        assert_eq!(wire[4..6], [0xa0, 0x82]);
        assert_eq!(wire[8..8 + certs_len], *RFC_8410);
        assert_eq!(wire[8 + certs_len..10 + certs_len], [0xa1, CRL.len() as u8]);
        assert_eq!(wire[10 + certs_len..], *CRL);
        let back = OriginatorInfo::decode(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(back, value);
        assert_eq!(back.certificates().unwrap().len(), 1);
    }

    #[test]
    fn swapped_or_universal_set_tags_are_rejected() {
        for (wire, error) in [
            (&b"\x30\x04\xa1\x00\xa0\x00"[..], Asn1Error::TrailingData),
            (&b"\x30\x02\x31\x00"[..], Asn1Error::TrailingData),
        ] {
            assert_eq!(
                OriginatorInfo::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
