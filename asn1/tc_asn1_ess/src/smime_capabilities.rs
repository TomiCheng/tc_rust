//! RFC 8551 §2.5.2 `SMIMECapabilities`, the value of the smimeCapabilities
//! attribute.
//!
//! ```text
//! SMIMECapabilities ::= SEQUENCE OF SMIMECapability
//! ```

use alloc::vec::Vec;

use tc_asn1::Asn1Oid;
use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::SmimeCapability;

/// The sender's capabilities, most preferred first.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SmimeCapabilities {
    capabilities: Asn1SequenceOf<SmimeCapability>,
}

impl SmimeCapabilities {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<SmimeCapability>) -> Self {
        Self {
            capabilities: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn capabilities(&self) -> &[SmimeCapability] {
        self.capabilities.elements()
    }

    /// Returns the capabilities with this identifier, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn capabilities_for<'a>(
        &'a self,
        capability_id: &'a Asn1Oid,
    ) -> impl Iterator<Item = &'a SmimeCapability> + 'a {
        self.capabilities()
            .iter()
            .filter(move |capability| capability.capability_id() == capability_id)
    }
}

impl DecodeContent for SmimeCapabilities {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let capabilities = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { capabilities })
    }
}

impl DecodeInner for SmimeCapabilities {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, capabilities) = Asn1SequenceOf::<SmimeCapability>::decode_inner(buff, context)?;
        Ok((len, Self { capabilities }))
    }
}

impl EncodeContent for SmimeCapabilities {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.capabilities.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.capabilities.encode_content(rules, out)
    }
}

impl Decode for SmimeCapabilities {}

impl Tagged for SmimeCapabilities {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SmimeCapabilities {}

impl Encode for SmimeCapabilities {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
