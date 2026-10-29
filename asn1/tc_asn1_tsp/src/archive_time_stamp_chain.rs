//! RFC 4998 §5 `ArchiveTimeStampChain`, time-stamps renewed under one hash
//! algorithm.
//!
//! ```text
//! ArchiveTimeStampChain ::= SEQUENCE OF ArchiveTimeStamp
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::ArchiveTimeStamp;

/// The archive time-stamps, oldest first.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ArchiveTimeStampChain {
    archive_time_stamps: Asn1SequenceOf<ArchiveTimeStamp>,
}

impl ArchiveTimeStampChain {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<ArchiveTimeStamp>) -> Self {
        Self {
            archive_time_stamps: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn archive_time_stamps(&self) -> &[ArchiveTimeStamp] {
        self.archive_time_stamps.elements()
    }
}

impl DecodeContent for ArchiveTimeStampChain {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let archive_time_stamps = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self {
            archive_time_stamps,
        })
    }
}

impl DecodeInner for ArchiveTimeStampChain {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, archive_time_stamps) =
            Asn1SequenceOf::<ArchiveTimeStamp>::decode_inner(buff, context)?;
        Ok((
            len,
            Self {
                archive_time_stamps,
            },
        ))
    }
}

impl EncodeContent for ArchiveTimeStampChain {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.archive_time_stamps.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.archive_time_stamps.encode_content(rules, out)
    }
}

impl Decode for ArchiveTimeStampChain {}

impl Tagged for ArchiveTimeStampChain {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ArchiveTimeStampChain {}

impl Encode for ArchiveTimeStampChain {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
