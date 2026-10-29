//! RFC 2986 §4.2 `CertificationRequest`, a PKCS #10 request signed with the
//! subject's key.
//!
//! ```text
//! CertificationRequest ::= SEQUENCE {
//!     certificationRequestInfo CertificationRequestInfo,
//!     signatureAlgorithm       AlgorithmIdentifier{{ SignatureAlgorithms }},
//!     signature                BIT STRING }
//! ```

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::CertificationRequestInfo;

/// The request, the algorithm it was signed with and the signature.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertificationRequest {
    certification_request_info: CertificationRequestInfo,
    signature_algorithm: AlgorithmIdentifier,
    signature: Asn1BitString,
}

impl CertificationRequest {
    /// The request, its signature algorithm and the signature.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        certification_request_info: CertificationRequestInfo,
        signature_algorithm: AlgorithmIdentifier,
        signature: Asn1BitString,
    ) -> Self {
        Self {
            certification_request_info,
            signature_algorithm,
            signature,
        }
    }

    /// Returns the signed part of the request.
    /// Variable time: branches only on the encoding structure.
    pub fn certification_request_info(&self) -> &CertificationRequestInfo {
        &self.certification_request_info
    }

    /// Returns the signature algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// Returns the signature.
    /// Variable time: branches only on the encoding structure.
    pub fn signature(&self) -> &Asn1BitString {
        &self.signature
    }
}

impl DecodeContent for CertificationRequest {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let certification_request_info = fields.get()?;
        let signature_algorithm = fields.get()?;
        let signature = fields.get()?;
        fields.end()?;
        let value = Self {
            certification_request_info,
            signature_algorithm,
            signature,
        };
        Ok(value)
    }
}

impl DecodeInner for CertificationRequest {
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

impl EncodeContent for CertificationRequest {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.certification_request_info.encoded_len(rules)
            + self.signature_algorithm.encoded_len(rules)
            + self.signature.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.certification_request_info.encode(rules, out)?;
        at += self.signature_algorithm.encode(rules, &mut out[at..])?;
        at += self.signature.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for CertificationRequest {}

impl Tagged for CertificationRequest {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertificationRequest {}

impl Encode for CertificationRequest {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
