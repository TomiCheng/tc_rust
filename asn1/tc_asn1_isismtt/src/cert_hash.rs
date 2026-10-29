//! Common PKI `CertHash`, the value of the certHash OCSP extension: the
//! hash of the certificate whose status was asked.
//!
//! ```text
//! CertHash ::= SEQUENCE {
//!     hashAlgorithm   AlgorithmIdentifier,
//!     certificateHash OCTET STRING }
//! ```

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The hash of a whole certificate and its algorithm.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertHash {
    hash_algorithm: AlgorithmIdentifier,
    certificate_hash: Asn1OctetString,
}

impl CertHash {
    /// The algorithm and the hash.
    /// Variable time: branches only on the encoding structure.
    pub fn new(hash_algorithm: AlgorithmIdentifier, certificate_hash: Asn1OctetString) -> Self {
        Self {
            hash_algorithm,
            certificate_hash,
        }
    }

    /// Returns the hash algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn hash_algorithm(&self) -> &AlgorithmIdentifier {
        &self.hash_algorithm
    }

    /// Returns the hash of the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn certificate_hash(&self) -> &Asn1OctetString {
        &self.certificate_hash
    }
}

impl DecodeContent for CertHash {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let hash_algorithm = fields.get()?;
        let certificate_hash = fields.get()?;
        fields.end()?;
        let value = Self {
            hash_algorithm,
            certificate_hash,
        };
        Ok(value)
    }
}

impl DecodeInner for CertHash {
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

impl EncodeContent for CertHash {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.hash_algorithm.encoded_len(rules) + self.certificate_hash.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.hash_algorithm.encode(rules, out)?;
        at += self.certificate_hash.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for CertHash {}

impl Tagged for CertHash {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertHash {}

impl Encode for CertHash {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
