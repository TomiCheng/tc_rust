//! RFC 2634 §5.4 `SigningCertificate`, the value of the signingCertificate attribute: the
//! certificates the signer used, first the signer's own.
//!
//! ```text
//! SigningCertificate ::= SEQUENCE {
//!     certs    SEQUENCE OF ESSCertID,
//!     policies SEQUENCE OF PolicyInformation OPTIONAL }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::ext::PolicyInformation;

use crate::EssCertId;

/// The signing certificate and others in its path, and the policies that apply.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SigningCertificate {
    certs: Asn1SequenceOf<EssCertId>,
    policies: Option<Asn1SequenceOf<PolicyInformation>>,
}

impl SigningCertificate {
    /// The certificates, the signer's own first, without policies.
    /// Variable time: branches only on the encoding structure.
    pub fn new(certs: Vec<EssCertId>) -> Self {
        Self {
            certs: Asn1SequenceOf::new(certs),
            policies: None,
        }
    }

    /// Sets the policies under which the signing certificate may be used.
    /// Variable time: branches only on the encoding structure.
    pub fn with_policies(mut self, policies: Vec<PolicyInformation>) -> Self {
        self.policies = Some(Asn1SequenceOf::new(policies));
        self
    }

    /// Returns the certificates in order, the signer's own first.
    /// Variable time: branches only on the encoding structure.
    pub fn certs(&self) -> &[EssCertId] {
        self.certs.elements()
    }

    /// Returns the policies, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn policies(&self) -> Option<&[PolicyInformation]> {
        self.policies.as_ref().map(Asn1SequenceOf::elements)
    }
}

impl DecodeContent for SigningCertificate {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let certs = fields.get()?;
        let policies = fields.get_opt()?;
        fields.end()?;
        let value = Self { certs, policies };
        Ok(value)
    }
}

impl DecodeInner for SigningCertificate {
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

impl EncodeContent for SigningCertificate {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.certs.encoded_len(rules) + self.policies.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.certs.encode(rules, out)?;
        if let Some(v) = &self.policies {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for SigningCertificate {}

impl Tagged for SigningCertificate {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SigningCertificate {}

impl Encode for SigningCertificate {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
