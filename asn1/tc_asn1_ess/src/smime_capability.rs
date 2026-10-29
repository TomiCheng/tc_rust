//! RFC 8551 §2.5.2 `SMIMECapability`, one algorithm or preference a sender
//! supports.
//!
//! ```text
//! SMIMECapability ::= SEQUENCE {
//!     capabilityID OBJECT IDENTIFIER,
//!     parameters   ANY DEFINED BY capabilityID OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A capability by identifier, with parameters such as an RC2 key size.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SmimeCapability {
    capability_id: Asn1Oid,
    parameters: Option<Asn1Any>,
}

impl SmimeCapability {
    /// A capability without parameters.
    /// Variable time: branches only on the encoding structure.
    pub fn new(capability_id: Asn1Oid) -> Self {
        Self {
            capability_id,
            parameters: None,
        }
    }

    /// Sets the parameters.
    /// Variable time: branches only on the encoding structure.
    pub fn with_parameters(mut self, parameters: Asn1Any) -> Self {
        self.parameters = Some(parameters);
        self
    }

    /// Returns the capability.
    /// Variable time: branches only on the encoding structure.
    pub fn capability_id(&self) -> &Asn1Oid {
        &self.capability_id
    }

    /// Returns the parameters, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn parameters(&self) -> Option<&Asn1Any> {
        self.parameters.as_ref()
    }
}

impl DecodeContent for SmimeCapability {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let capability_id = fields.get()?;
        let parameters = fields.get_any_opt()?;
        fields.end()?;
        let value = Self {
            capability_id,
            parameters,
        };
        Ok(value)
    }
}

impl DecodeInner for SmimeCapability {
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

impl EncodeContent for SmimeCapability {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.capability_id.encoded_len(rules)
            + self.parameters.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.capability_id.encode(rules, out)?;
        if let Some(v) = &self.parameters {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for SmimeCapability {}

impl Tagged for SmimeCapability {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SmimeCapability {}

impl Encode for SmimeCapability {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
