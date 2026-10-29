//! RFC 5126 §6.3.4 `RevocationValues`, the value of the revocation-values attribute.
//!
//! ```text
//! RevocationValues ::= SEQUENCE {
//!     crlVals      [0] SEQUENCE OF CertificateList   OPTIONAL,
//!     ocspVals     [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
//!     otherRevVals [2] OtherRevVals                  OPTIONAL }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_ocsp::BasicOcspResponse;
use tc_asn1_x509::crl::CertificateList;

use crate::OtherRevVals;

/// The CRLs, OCSP responses and other data used to validate the signature.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct RevocationValues {
    crl_vals: Option<Asn1SequenceOf<CertificateList>>,
    ocsp_vals: Option<Asn1SequenceOf<BasicOcspResponse>>,
    other_rev_vals: Option<OtherRevVals>,
}

impl RevocationValues {
    /// Values with every field absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new() -> Self {
        Self {
            crl_vals: None,
            ocsp_vals: None,
            other_rev_vals: None,
        }
    }

    /// Sets the CRLs.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crl_vals(mut self, crl_vals: Vec<CertificateList>) -> Self {
        self.crl_vals = Some(Asn1SequenceOf::new(crl_vals));
        self
    }

    /// Sets the OCSP responses.
    /// Variable time: branches only on the encoding structure.
    pub fn with_ocsp_vals(mut self, ocsp_vals: Vec<BasicOcspResponse>) -> Self {
        self.ocsp_vals = Some(Asn1SequenceOf::new(ocsp_vals));
        self
    }

    /// Sets other revocation data.
    /// Variable time: branches only on the encoding structure.
    pub fn with_other_rev_vals(mut self, other_rev_vals: OtherRevVals) -> Self {
        self.other_rev_vals = Some(other_rev_vals);
        self
    }

    /// Returns the CRLs, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_vals(&self) -> Option<&[CertificateList]> {
        self.crl_vals.as_ref().map(Asn1SequenceOf::elements)
    }

    /// Returns the OCSP responses, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn ocsp_vals(&self) -> Option<&[BasicOcspResponse]> {
        self.ocsp_vals.as_ref().map(Asn1SequenceOf::elements)
    }

    /// Returns other revocation data, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn other_rev_vals(&self) -> Option<&OtherRevVals> {
        self.other_rev_vals.as_ref()
    }
}

impl DecodeContent for RevocationValues {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let crl_vals = fields.get_explicit_opt::<Asn1SequenceOf<CertificateList>>([0xa0])?;
        let ocsp_vals = fields.get_explicit_opt::<Asn1SequenceOf<BasicOcspResponse>>([0xa1])?;
        let other_rev_vals = fields.get_explicit_opt::<OtherRevVals>([0xa2])?;
        fields.end()?;
        let value = Self {
            crl_vals,
            ocsp_vals,
            other_rev_vals,
        };
        Ok(value)
    }
}

impl DecodeInner for RevocationValues {
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

impl EncodeContent for RevocationValues {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.crl_vals
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .ocsp_vals
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self
                .other_rev_vals
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa2], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.crl_vals {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.ocsp_vals {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.other_rev_vals {
            at += Explicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for RevocationValues {}

impl Tagged for RevocationValues {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RevocationValues {}

impl Encode for RevocationValues {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
