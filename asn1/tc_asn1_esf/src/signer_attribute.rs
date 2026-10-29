//! RFC 5126 §5.11.3 `SignerAttribute`, the value of the signer-attributes
//! attribute.
//!
//! ```text
//! SignerAttribute ::= SEQUENCE OF CHOICE {
//!     claimedAttributes   [0] ClaimedAttributes,
//!     certifiedAttributes [1] CertifiedAttributes }
//! ClaimedAttributes ::= SEQUENCE OF Attribute
//! CertifiedAttributes ::= AttributeCertificate
//! ```
//!
//! Bouncy Castle reads only the first entry; this type reads them all.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::SignerAttributeEntry;

/// The signer's claimed and certified attributes, such as its role.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignerAttribute {
    entries: Asn1SequenceOf<SignerAttributeEntry>,
}

impl SignerAttribute {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<SignerAttributeEntry>) -> Self {
        Self {
            entries: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn entries(&self) -> &[SignerAttributeEntry] {
        self.entries.elements()
    }
}

impl DecodeContent for SignerAttribute {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let entries = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { entries })
    }
}

impl DecodeInner for SignerAttribute {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, entries) = Asn1SequenceOf::<SignerAttributeEntry>::decode_inner(buff, context)?;
        Ok((len, Self { entries }))
    }
}

impl EncodeContent for SignerAttribute {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.entries.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.entries.encode_content(rules, out)
    }
}

impl Decode for SignerAttribute {}

impl Tagged for SignerAttribute {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SignerAttribute {}

impl Encode for SignerAttribute {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
