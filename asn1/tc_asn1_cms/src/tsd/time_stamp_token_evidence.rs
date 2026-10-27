//! RFC 5544 `TimeStampTokenEvidence`, the time-stamp chain of time-stamped data.
//!
//! ```text
//! TimeStampTokenEvidence ::= SEQUENCE SIZE(1..MAX) OF TimeStampAndCRL
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::tsd::TimeStampAndCrl;

/// One or more time stamps, each with an optional CRL; an empty list is
/// `MalformedValue`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TimeStampTokenEvidence {
    tokens: Asn1SequenceOf<TimeStampAndCrl>,
}

impl TimeStampTokenEvidence {
    /// Rejects an empty list with `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(tokens: Vec<TimeStampAndCrl>) -> Result<Self, Asn1Error> {
        if tokens.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            tokens: Asn1SequenceOf::new(tokens),
        })
    }

    /// Returns the time stamps, oldest first.
    /// Variable time: branches only on the encoding structure.
    pub fn tokens(&self) -> &[TimeStampAndCrl] {
        self.tokens.elements()
    }
}

impl DecodeContent for TimeStampTokenEvidence {
    /// The elements, as under `30` on its own or `A0` in `Evidence`.
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let tokens = Asn1SequenceOf::<TimeStampAndCrl>::decode_content(value, context)?;
        Self::new(tokens.into_elements())
    }
}

impl DecodeInner for TimeStampTokenEvidence {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, tokens) = Asn1SequenceOf::<TimeStampAndCrl>::decode_inner(buff, context)?;
        Ok((len, Self::new(tokens.into_elements())?))
    }
}

impl EncodeContent for TimeStampTokenEvidence {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.tokens.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.tokens.encode_content(rules, out)
    }
}

impl Decode for TimeStampTokenEvidence {}

impl Tagged for TimeStampTokenEvidence {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for TimeStampTokenEvidence {}

impl Encode for TimeStampTokenEvidence {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
