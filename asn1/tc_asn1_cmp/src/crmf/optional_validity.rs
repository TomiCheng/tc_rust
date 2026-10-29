//! RFC 4211 §5 `OptionalValidity`, the validity a requester asks for.
//!
//! ```text
//! OptionalValidity ::= SEQUENCE {
//!     notBefore [0] Time OPTIONAL,
//!     notAfter  [1] Time OPTIONAL } -- at least one MUST be present
//! ```
//!
//! `Time` is a CHOICE, so its tags are explicit.

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::cert::Time;

/// The start and end of the validity asked for.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct OptionalValidity {
    not_before: Option<Time>,
    not_after: Option<Time>,
}

impl OptionalValidity {
    /// A validity with both bounds absent; RFC 4211 wants at least one.
    /// Variable time: branches only on the encoding structure.
    pub fn new() -> Self {
        Self {
            not_before: None,
            not_after: None,
        }
    }

    /// Sets the start.
    /// Variable time: branches only on the encoding structure.
    pub fn with_not_before(mut self, not_before: Time) -> Self {
        self.not_before = Some(not_before);
        self
    }

    /// Sets the end.
    /// Variable time: branches only on the encoding structure.
    pub fn with_not_after(mut self, not_after: Time) -> Self {
        self.not_after = Some(not_after);
        self
    }

    /// Returns the start, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn not_before(&self) -> Option<&Time> {
        self.not_before.as_ref()
    }

    /// Returns the end, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn not_after(&self) -> Option<&Time> {
        self.not_after.as_ref()
    }
}

impl DecodeContent for OptionalValidity {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let not_before = fields.get_explicit_opt::<Time>([0xa0])?;
        let not_after = fields.get_explicit_opt::<Time>([0xa1])?;
        fields.end()?;
        let value = Self {
            not_before,
            not_after,
        };
        Ok(value)
    }
}

impl DecodeInner for OptionalValidity {
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

impl EncodeContent for OptionalValidity {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.not_before
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .not_after
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.not_before {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.not_after {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for OptionalValidity {}

impl Tagged for OptionalValidity {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OptionalValidity {}

impl Encode for OptionalValidity {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
