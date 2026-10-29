//! RFC 6960 §4.2.1 `BasicOCSPResponse`, the response of type
//! `id-pkix-ocsp-basic`.
//!
//! ```text
//! BasicOCSPResponse ::= SEQUENCE {
//!     tbsResponseData    ResponseData,
//!     signatureAlgorithm AlgorithmIdentifier,
//!     signature          BIT STRING,
//!     certs              [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit,
    Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::Certificate;

use crate::ResponseData;

/// The response data, the responder's signature over it, and certificates to
/// check that signature.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct BasicOcspResponse {
    tbs_response_data: ResponseData,
    signature_algorithm: AlgorithmIdentifier,
    signature: Asn1BitString,
    certs: Option<Asn1SequenceOf<Certificate>>,
}

impl BasicOcspResponse {
    /// The response data and its signature, without certificates.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        tbs_response_data: ResponseData,
        signature_algorithm: AlgorithmIdentifier,
        signature: Asn1BitString,
    ) -> Self {
        Self {
            tbs_response_data,
            signature_algorithm,
            signature,
            certs: None,
        }
    }

    /// Sets the certificates that help verify the signature.
    /// Variable time: branches only on the encoding structure.
    pub fn with_certs(mut self, certs: Vec<Certificate>) -> Self {
        self.certs = Some(Asn1SequenceOf::new(certs));
        self
    }

    /// Returns the signed response data.
    /// Variable time: branches only on the encoding structure.
    pub fn tbs_response_data(&self) -> &ResponseData {
        &self.tbs_response_data
    }

    /// Returns the signature algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// Returns the signature value.
    /// Variable time: branches only on the encoding structure.
    pub fn signature(&self) -> &Asn1BitString {
        &self.signature
    }

    /// Returns the certificates in order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn certs(&self) -> Option<&[Certificate]> {
        self.certs.as_ref().map(Asn1SequenceOf::elements)
    }
}

impl DecodeContent for BasicOcspResponse {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let tbs_response_data = fields.get()?;
        let signature_algorithm = fields.get()?;
        let signature = fields.get()?;
        let certs = fields.get_explicit_opt::<Asn1SequenceOf<Certificate>>([0xa0])?;
        fields.end()?;
        let value = Self {
            tbs_response_data,
            signature_algorithm,
            signature,
            certs,
        };
        Ok(value)
    }
}

impl DecodeInner for BasicOcspResponse {
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

impl EncodeContent for BasicOcspResponse {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.tbs_response_data.encoded_len(rules)
            + self.signature_algorithm.encoded_len(rules)
            + self.signature.encoded_len(rules)
            + self
                .certs
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.tbs_response_data.encode(rules, out)?;
        at += self.signature_algorithm.encode(rules, &mut out[at..])?;
        at += self.signature.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.certs {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for BasicOcspResponse {}

impl Tagged for BasicOcspResponse {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for BasicOcspResponse {}

impl Encode for BasicOcspResponse {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
