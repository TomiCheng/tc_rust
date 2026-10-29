//! RFC 4210 §5.1 `PKIMessages`, CMP messages sent together.
//!
//! ```text
//! PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::PkiMessage;

/// One or more messages, also the body of a nested message.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PkiMessages {
    messages: Asn1SequenceOf<PkiMessage>,
}

impl PkiMessages {
    /// The elements, in order. None is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<PkiMessage>) -> Result<Self, Asn1Error> {
        if elements.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            messages: Asn1SequenceOf::new(elements),
        })
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn messages(&self) -> &[PkiMessage] {
        self.messages.elements()
    }
}

impl DecodeContent for PkiMessages {
    /// An empty sequence is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let messages = Asn1SequenceOf::decode_content(value, context)?;
        if messages.elements().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { messages })
    }
}

impl DecodeInner for PkiMessages {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, messages) = Asn1SequenceOf::<PkiMessage>::decode_inner(buff, context)?;
        if messages.elements().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((len, Self { messages }))
    }
}

impl EncodeContent for PkiMessages {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.messages.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.messages.encode_content(rules, out)
    }
}

impl Decode for PkiMessages {}

impl Tagged for PkiMessages {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PkiMessages {}

impl Encode for PkiMessages {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
