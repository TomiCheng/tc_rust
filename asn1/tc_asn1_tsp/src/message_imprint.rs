//! RFC 3161 §2.4.1 `MessageImprint`, the hash of the data time-stamped.
//!
//! ```text
//! MessageImprint ::= SEQUENCE {
//!     hashAlgorithm AlgorithmIdentifier,
//!     hashedMessage OCTET STRING }
//! ```

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// A hash algorithm and the hash of the data.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MessageImprint {
    hash_algorithm: AlgorithmIdentifier,
    hashed_message: Asn1OctetString,
}

impl MessageImprint {
    /// The hash algorithm and the hash.
    /// Variable time: branches only on the encoding structure.
    pub fn new(hash_algorithm: AlgorithmIdentifier, hashed_message: Asn1OctetString) -> Self {
        Self {
            hash_algorithm,
            hashed_message,
        }
    }

    /// Returns the hash algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn hash_algorithm(&self) -> &AlgorithmIdentifier {
        &self.hash_algorithm
    }

    /// Returns the hash of the data.
    /// Variable time: branches only on the encoding structure.
    pub fn hashed_message(&self) -> &Asn1OctetString {
        &self.hashed_message
    }
}

impl DecodeContent for MessageImprint {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let hash_algorithm = fields.get()?;
        let hashed_message = fields.get()?;
        fields.end()?;
        let value = Self {
            hash_algorithm,
            hashed_message,
        };
        Ok(value)
    }
}

impl DecodeInner for MessageImprint {
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

impl EncodeContent for MessageImprint {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.hash_algorithm.encoded_len(rules) + self.hashed_message.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.hash_algorithm.encode(rules, out)?;
        at += self.hashed_message.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for MessageImprint {}

impl Tagged for MessageImprint {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for MessageImprint {}

impl Encode for MessageImprint {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
