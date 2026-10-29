//! PKCS #7 (RFC 2315 §9.1) `SignedData`, Bouncy Castle's `Asn1.Pkcs.SignedData`.
//!
//! ```text
//! SignedData ::= SEQUENCE {
//!     version          Version,
//!     digestAlgorithms DigestAlgorithmIdentifiers,
//!     contentInfo      ContentInfo,
//!     certificates     [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
//!     crls             [1] IMPLICIT CertificateRevocationLists OPTIONAL,
//!     signerInfos      SignerInfos }
//! ```
//!
//! It differs from CMS `SignedData` in carrying a whole `ContentInfo`, whose
//! content can be of any type, where CMS wraps the content in an OCTET STRING.
//! The certificates, CRLs and signer infos are the CMS types, which cover the
//! PKCS #7 forms.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SetOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};
use tc_asn1_cms::content::{CertificateChoices, ContentInfo, RevocationInfoChoice};
use tc_asn1_cms::signed::SignerInfo;
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The digest algorithms, the signed content, certificates and CRLs to help verify
/// it, and the signers.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignedData {
    version: Option<Asn1Integer>,
    digest_algorithms: Asn1SetOf<AlgorithmIdentifier>,
    content_info: ContentInfo,
    certificates: Option<Asn1SetOf<CertificateChoices>>,
    crls: Option<Asn1SetOf<RevocationInfoChoice>>,
    signer_infos: Asn1SetOf<SignerInfo>,
}

impl SignedData {
    /// The digest algorithms, the content and the signers, without certificates or
    /// CRLs.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        digest_algorithms: Vec<AlgorithmIdentifier>,
        content_info: ContentInfo,
        signer_infos: Vec<SignerInfo>,
    ) -> Self {
        Self {
            version: None,
            digest_algorithms: Asn1SetOf::new(digest_algorithms),
            content_info,
            certificates: None,
            crls: None,
            signer_infos: Asn1SetOf::new(signer_infos),
        }
    }

    /// Sets the certificates.
    /// Variable time: branches only on the encoding structure.
    pub fn with_certificates(mut self, certificates: Vec<CertificateChoices>) -> Self {
        self.certificates = Some(Asn1SetOf::new(certificates));
        self
    }

    /// Sets the CRLs.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crls(mut self, crls: Vec<RevocationInfoChoice>) -> Self {
        self.crls = Some(Asn1SetOf::new(crls));
        self
    }

    /// Returns the decoded version, or the one RFC 2315 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// Always 1.
    fn derived_version(&self) -> Asn1Integer {
        1.into()
    }

    /// Returns the digest algorithms in construction or wire order.
    /// Variable time: branches only on the encoding structure.
    pub fn digest_algorithms(&self) -> &[AlgorithmIdentifier] {
        self.digest_algorithms.members()
    }

    /// Returns the signed content.
    /// Variable time: branches only on the encoding structure.
    pub fn content_info(&self) -> &ContentInfo {
        &self.content_info
    }

    /// Returns the certificates in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn certificates(&self) -> Option<&[CertificateChoices]> {
        self.certificates.as_ref().map(Asn1SetOf::members)
    }

    /// Returns the CRLs in construction or wire order, if present.
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
        let content_info = fields.get()?;
        let certificates = fields.get_implicit_opt([0xa0])?;
        let crls = fields.get_implicit_opt([0xa1])?;
        let signer_infos = fields.get()?;
        fields.end()?;
        let mut value = Self {
            version: None,
            digest_algorithms,
            content_info,
            certificates,
            crls,
            signer_infos,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
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
            + self.content_info.encoded_len(rules)
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
        at += self.content_info.encode(rules, &mut out[at..])?;
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
