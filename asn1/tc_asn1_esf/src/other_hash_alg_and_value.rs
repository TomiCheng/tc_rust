//! RFC 5126 §5.8.1 `OtherHashAlgAndValue`, a hash with its algorithm.
//!
//! ```text
//! OtherHashAlgAndValue ::= SEQUENCE {
//!     hashAlgorithm AlgorithmIdentifier,
//!     hashValue     OtherHashValue }
//! OtherHashValue ::= OCTET STRING
//! ```

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// A hash value and the algorithm that produced it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtherHashAlgAndValue {
    hash_algorithm: AlgorithmIdentifier,
    hash_value: Asn1OctetString,
}

impl OtherHashAlgAndValue {
    /// The algorithm and the hash value.
    /// Variable time: branches only on the encoding structure.
    pub fn new(hash_algorithm: AlgorithmIdentifier, hash_value: Asn1OctetString) -> Self {
        Self {
            hash_algorithm,
            hash_value,
        }
    }

    /// Returns the hash algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn hash_algorithm(&self) -> &AlgorithmIdentifier {
        &self.hash_algorithm
    }

    /// Returns the hash value.
    /// Variable time: branches only on the encoding structure.
    pub fn hash_value(&self) -> &Asn1OctetString {
        &self.hash_value
    }
}

impl DecodeContent for OtherHashAlgAndValue {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let hash_algorithm = fields.get()?;
        let hash_value = fields.get()?;
        fields.end()?;
        let value = Self {
            hash_algorithm,
            hash_value,
        };
        Ok(value)
    }
}

impl DecodeInner for OtherHashAlgAndValue {
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

impl EncodeContent for OtherHashAlgAndValue {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.hash_algorithm.encoded_len(rules) + self.hash_value.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.hash_algorithm.encode(rules, out)?;
        at += self.hash_value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for OtherHashAlgAndValue {}

impl Tagged for OtherHashAlgAndValue {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OtherHashAlgAndValue {}

impl Encode for OtherHashAlgAndValue {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
