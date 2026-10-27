//! RFC 5652 §5.1 `SignedData`.
//!
//! ```text
//! SignedData ::= SEQUENCE {
//!     version CMSVersion,
//!     digestAlgorithms DigestAlgorithmIdentifiers,
//!     encapContentInfo EncapsulatedContentInfo,
//!     certificates [0] IMPLICIT CertificateSet OPTIONAL,
//!     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//!     signerInfos SignerInfos }
//! DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
//! SignerInfos ::= SET OF SignerInfo
//! EncapsulatedContentInfo ::= SEQUENCE {
//!     eContentType ContentType,
//!     eContent [0] EXPLICIT OCTET STRING OPTIONAL }
//! ```
//!
//! The encapsulated content is held as a [`ContentInfo`], as Bouncy Castle
//! does, so PKCS #7 content other than an OCTET STRING, such as Authenticode's,
//! is kept too.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SetOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::content::{CertificateChoices, ContentInfo, ContentType, RevocationInfoChoice};
use crate::signed::SignerInfo;

/// Content with any number of signatures, and the certificates and revocation
/// information to check them.
///
/// The version follows RFC 5652 §5.1 from the certificates, the revocation
/// information, the signers and the content type, unless
/// [`with_version`](Self::with_version) pins another, as Authenticode's version
/// 1 does; a decoded version that differs from the rule is kept.
///
/// ```
/// use tc_asn1::{Asn1Any, Decode, DecodingOptions, Encode, EncodingOptions, tag};
/// use tc_asn1_cms::content::{ContentInfo, ContentType, SignedData};
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// // A certificates-only message: no content and no signers.
/// let degenerate = SignedData::new(Vec::new(), ContentInfo::new(ContentType::DATA.oid()), Vec::new())
///     .with_certificates(Vec::new());
/// assert_eq!(degenerate.version(), 1.into());
///
/// let message = ContentInfo::new(ContentType::SIGNED_DATA.oid())
///     .with_content(Asn1Any::decode(&degenerate.encode_to_vec(&EncodingOptions::DER)?, &DecodingOptions::default())?.1);
/// let der = message.encode_to_vec(&EncodingOptions::DER)?;
/// let inner = ContentInfo::decode_der(&der, &DecodingOptions::default())?.1;
/// let back = SignedData::decode_der(inner.content().unwrap().raw(), &DecodingOptions::default())?.1;
/// assert_eq!(back, degenerate);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignedData {
    version: Option<Asn1Integer>,
    digest_algorithms: Asn1SetOf<AlgorithmIdentifier>,
    encap_content_info: ContentInfo,
    certificates: Option<Asn1SetOf<CertificateChoices>>,
    crls: Option<Asn1SetOf<RevocationInfoChoice>>,
    signer_infos: Asn1SetOf<SignerInfo>,
}

impl SignedData {
    /// Content and its signers, without certificates or revocation information.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        digest_algorithms: Vec<AlgorithmIdentifier>,
        encap_content_info: ContentInfo,
        signer_infos: Vec<SignerInfo>,
    ) -> Self {
        Self {
            version: None,
            digest_algorithms: Asn1SetOf::new(digest_algorithms),
            encap_content_info,
            certificates: None,
            crls: None,
            signer_infos: Asn1SetOf::new(signer_infos),
        }
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

    /// Pins the version instead of deriving it.
    /// Variable time: branches only on the encoding structure.
    pub fn with_version(mut self, version: Asn1Integer) -> Self {
        self.version = Some(version);
        self
    }

    /// Returns the pinned or decoded version, or the one RFC 5652 §5.1 calls
    /// for. Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// RFC 5652 §5.1, as Bouncy Castle's `CalculateVersionField`.
    fn derived_version(&self) -> Asn1Integer {
        let certificates = self.certificates().unwrap_or_default();
        let crls = self.crls().unwrap_or_default();
        if certificates
            .iter()
            .any(|c| matches!(c, CertificateChoices::Other(_)))
            || crls
                .iter()
                .any(|c| matches!(c, RevocationInfoChoice::Other(_)))
        {
            return 5.into();
        }
        if certificates
            .iter()
            .any(|c| matches!(c, CertificateChoices::V2AttrCert(_)))
        {
            return 4.into();
        }
        let three = Asn1Integer::from(3);
        if certificates
            .iter()
            .any(|c| matches!(c, CertificateChoices::V1AttrCert(_)))
            || self.signer_infos().iter().any(|s| s.version() == three)
            || ContentType::from_oid(self.encap_content_info.content_type())
                != Some(ContentType::DATA)
        {
            return three;
        }
        1.into()
    }

    /// Returns the digest algorithms in construction or wire order.
    /// Variable time: branches only on the encoding structure.
    pub fn digest_algorithms(&self) -> &[AlgorithmIdentifier] {
        self.digest_algorithms.members()
    }

    /// Returns the encapsulated content.
    /// Variable time: branches only on the encoding structure.
    pub fn encap_content_info(&self) -> &ContentInfo {
        &self.encap_content_info
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

    /// Returns the signers in construction or wire order.
    /// Variable time: branches only on the encoding structure.
    pub fn signer_infos(&self) -> &[SignerInfo] {
        self.signer_infos.members()
    }
}

impl DecodeContent for SignedData {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let digest_algorithms = fields.get()?;
        let encap_content_info = fields.get()?;
        let certificates = fields.get_implicit_opt([0xa0])?;
        let crls = fields.get_implicit_opt([0xa1])?;
        let signer_infos = fields.get()?;
        fields.end()?;
        let mut data = Self {
            version: None,
            digest_algorithms,
            encap_content_info,
            certificates,
            crls,
            signer_infos,
        };
        if version != data.derived_version() {
            data.version = Some(version);
        }
        Ok(data)
    }
}

impl DecodeInner for SignedData {
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

impl EncodeContent for SignedData {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.digest_algorithms.encoded_len(rules)
            + self.encap_content_info.encoded_len(rules)
            + self
                .certificates
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .crls
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa1], v).encoded_len(rules))
            + self.signer_infos.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.digest_algorithms.encode(rules, &mut out[at..])?;
        at += self.encap_content_info.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.certificates {
            at += Implicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.crls {
            at += Implicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        at += self.signer_infos.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for SignedData {}

impl Tagged for SignedData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SignedData {}

impl Encode for SignedData {
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
    use alloc::vec::Vec;

    use tc_asn1::{
        Asn1Any, Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions, tag,
    };

    use super::SignedData;
    use crate::content::{
        CertificateChoices, ContentInfo, ContentType, OtherCertificateFormat,
        OtherRevocationInfoFormat, RevocationInfoChoice,
    };
    use crate::fixtures::{by_issuer, by_key_identifier, certificate, crl, sha256};

    fn data() -> ContentInfo {
        ContentInfo::new(ContentType::DATA.oid())
            .with_content(Asn1Any::primitive(tag::OCTET_STRING, b"signed text"))
    }

    fn version(data: &SignedData) -> Asn1Integer {
        data.version()
    }

    #[test]
    fn the_version_follows_the_rfc_5652_rules_in_order() {
        let base = || SignedData::new(vec![sha256()], data(), vec![by_issuer()]);
        assert_eq!(version(&base()), 1.into());
        assert_eq!(
            version(&base().with_certificates(vec![certificate()])),
            1.into()
        );
        // A non-Data content type, or a version 3 signer, makes it 3.
        let tsa = SignedData::new(
            vec![sha256()],
            ContentInfo::new("1.2.840.113549.1.9.16.1.4".parse().unwrap()),
            vec![by_issuer()],
        );
        assert_eq!(version(&tsa), 3.into());
        assert_eq!(
            version(&SignedData::new(
                vec![sha256()],
                data(),
                vec![by_key_identifier()]
            )),
            3.into()
        );
        // A v1 attribute certificate makes it 3, a v2 one 4.
        let v1_attr = CertificateChoices::V1AttrCert(
            Asn1Any::decode(b"\xa1\x02\x05\x00", &DecodingOptions::default())
                .unwrap()
                .1,
        );
        assert_eq!(version(&base().with_certificates(vec![v1_attr])), 3.into());
        // Another certificate or revocation format makes it 5.
        let other_certificate = CertificateChoices::Other(OtherCertificateFormat::new(
            "1.2.3".parse().unwrap(),
            Asn1Any::primitive(tag::OCTET_STRING, b"x"),
        ));
        assert_eq!(
            version(&base().with_certificates(vec![other_certificate])),
            5.into()
        );
        let ocsp = RevocationInfoChoice::Other(OtherRevocationInfoFormat::new(
            OtherRevocationInfoFormat::OCSP_RESPONSE.oid(),
            Asn1Any::primitive(tag::OCTET_STRING, b"r"),
        ));
        assert_eq!(version(&base().with_crls(vec![ocsp])), 5.into());
        assert_eq!(
            version(&base().with_crls(vec![RevocationInfoChoice::from(crl())])),
            1.into()
        );
    }

    #[test]
    fn a_full_message_round_trips_under_every_rule() {
        let value = SignedData::new(
            vec![sha256()],
            data(),
            vec![by_issuer(), by_key_identifier()],
        )
        .with_certificates(vec![certificate()])
        .with_crls(vec![RevocationInfoChoice::from(crl())]);
        assert_eq!(value.version(), 3.into());
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::DER,
            EncodingOptions::CER,
        ] {
            let wire = value.encode_to_vec(&rules).unwrap();
            let back = SignedData::decode(&wire, &DecodingOptions::default())
                .unwrap()
                .1;
            assert_eq!(back, value);
            assert_eq!(back.signer_infos().len(), 2);
        }
    }

    #[test]
    fn a_pinned_or_decoded_version_that_breaks_the_rule_is_kept() {
        let pinned = SignedData::new(
            vec![sha256()],
            ContentInfo::new("1.3.6.1.4.1.311.2.1.4".parse().unwrap()),
            vec![by_issuer()],
        )
        .with_version(1.into());
        let wire = pinned.encode_to_vec(&EncodingOptions::DER).unwrap();
        // 30 81 LL: the long-form length puts the version at offset 3.
        assert_eq!(wire[3..6], [0x02, 0x01, 0x01]);
        let back = SignedData::decode_der(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(back.version(), 1.into());
        assert_eq!(back, pinned);
    }

    #[test]
    fn missing_signer_infos_and_misordered_sets_are_rejected() {
        let der = |value: &dyn Encode| value.encode_to_vec(&EncodingOptions::DER).unwrap();
        let value = SignedData::new(vec![sha256()], data(), Vec::new());
        let head = [
            der(&value.version()),
            der(&tc_asn1::Asn1SetOf::new(vec![sha256()])),
            der(value.encap_content_info()),
        ]
        .concat();
        let sequence = |body: &[u8]| [&[0x30, body.len() as u8][..], body].concat();

        assert_eq!(
            SignedData::decode_der(&sequence(&head), &DecodingOptions::default()),
            Err(Asn1Error::Truncated)
        );
        // crls [1] before certificates [0]: [0] is then read as signerInfos.
        let swapped = sequence(&[head, vec![0xa1, 0x00, 0xa0, 0x00, 0x31, 0x00]].concat());
        assert_eq!(
            SignedData::decode_der(&swapped, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
