//! RFC 4998 §5 `ArchiveTimeStampSequence`, chains renewed as hash algorithms
//! age.
//!
//! ```text
//! ArchiveTimeStampSequence ::= SEQUENCE OF ArchiveTimeStampChain
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::ArchiveTimeStampChain;

/// The chains, oldest first.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ArchiveTimeStampSequence {
    chains: Asn1SequenceOf<ArchiveTimeStampChain>,
}

impl ArchiveTimeStampSequence {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<ArchiveTimeStampChain>) -> Self {
        Self {
            chains: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn chains(&self) -> &[ArchiveTimeStampChain] {
        self.chains.elements()
    }
}

impl DecodeContent for ArchiveTimeStampSequence {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let chains = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { chains })
    }
}

impl DecodeInner for ArchiveTimeStampSequence {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, chains) = Asn1SequenceOf::<ArchiveTimeStampChain>::decode_inner(buff, context)?;
        Ok((len, Self { chains }))
    }
}

impl EncodeContent for ArchiveTimeStampSequence {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.chains.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.chains.encode_content(rules, out)
    }
}

impl Decode for ArchiveTimeStampSequence {}

impl Tagged for ArchiveTimeStampSequence {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ArchiveTimeStampSequence {}

impl Encode for ArchiveTimeStampSequence {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
