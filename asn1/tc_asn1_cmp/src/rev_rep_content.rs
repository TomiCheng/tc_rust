//! RFC 4210 §5.3.10 `RevRepContent`, the body of a revocation response.
//!
//! ```text
//! RevRepContent ::= SEQUENCE {
//!     status   SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
//!     revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,
//!     crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList OPTIONAL }
//! ```
//!
//! The module uses explicit tags.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::crl::CertificateList;

use crate::PkiStatusInfo;
use crate::crmf::CertId;

/// One status per request, the certificates revoked, and CRLs.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RevRepContent {
    status: Asn1SequenceOf<PkiStatusInfo>,
    rev_certs: Option<Asn1SequenceOf<CertId>>,
    crls: Option<Asn1SequenceOf<CertificateList>>,
}

impl RevRepContent {
    /// The statuses, without certificates or CRLs.
    /// Variable time: branches only on the encoding structure.
    pub fn new(status: Vec<PkiStatusInfo>) -> Self {
        Self {
            status: Asn1SequenceOf::new(status),
            rev_certs: None,
            crls: None,
        }
    }

    /// Sets the revoked certificates.
    /// Variable time: branches only on the encoding structure.
    pub fn with_rev_certs(mut self, rev_certs: Vec<CertId>) -> Self {
        self.rev_certs = Some(Asn1SequenceOf::new(rev_certs));
        self
    }

    /// Sets the CRLs.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crls(mut self, crls: Vec<CertificateList>) -> Self {
        self.crls = Some(Asn1SequenceOf::new(crls));
        self
    }

    /// Returns the statuses, one per request.
    /// Variable time: branches only on the encoding structure.
    pub fn status(&self) -> &[PkiStatusInfo] {
        self.status.elements()
    }

    /// Returns the revoked certificates, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn rev_certs(&self) -> Option<&[CertId]> {
        self.rev_certs.as_ref().map(Asn1SequenceOf::elements)
    }

    /// Returns the CRLs, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crls(&self) -> Option<&[CertificateList]> {
        self.crls.as_ref().map(Asn1SequenceOf::elements)
    }
}

impl DecodeContent for RevRepContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let status = fields.get()?;
        let rev_certs = fields.get_explicit_opt::<Asn1SequenceOf<CertId>>([0xa0])?;
        let crls = fields.get_explicit_opt::<Asn1SequenceOf<CertificateList>>([0xa1])?;
        fields.end()?;
        let value = Self {
            status,
            rev_certs,
            crls,
        };
        Ok(value)
    }
}

impl DecodeInner for RevRepContent {
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

impl EncodeContent for RevRepContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.status.encoded_len(rules)
            + self
                .rev_certs
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .crls
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.status.encode(rules, out)?;
        if let Some(v) = &self.rev_certs {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.crls {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for RevRepContent {}

impl Tagged for RevRepContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RevRepContent {}

impl Encode for RevRepContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
