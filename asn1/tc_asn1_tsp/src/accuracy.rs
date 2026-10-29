//! RFC 3161 §2.4.2 `Accuracy`, the deviation around the time in a token.
//!
//! ```text
//! Accuracy ::= SEQUENCE {
//!     seconds    INTEGER           OPTIONAL,
//!     millis [0] INTEGER (1..999)  OPTIONAL,
//!     micros [1] INTEGER (1..999)  OPTIONAL }
//! ```
//!
//! The module uses implicit tags, so `millis` is `80` and `micros` `81`.

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};

/// Seconds, milliseconds and microseconds, any of which may be absent and
/// count as zero.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Accuracy {
    seconds: Option<Asn1Integer>,
    millis: Option<Asn1Integer>,
    micros: Option<Asn1Integer>,
}

impl Accuracy {
    /// An accuracy with every field absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new() -> Self {
        Self {
            seconds: None,
            millis: None,
            micros: None,
        }
    }

    /// Sets the seconds.
    /// Variable time: branches only on the encoding structure.
    pub fn with_seconds(mut self, seconds: Asn1Integer) -> Self {
        self.seconds = Some(seconds);
        self
    }

    /// Sets the milliseconds; outside 1 to 999 is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn with_millis(mut self, millis: Asn1Integer) -> Result<Self, Asn1Error> {
        self.millis = Some(sub_second(millis)?);
        Ok(self)
    }

    /// Sets the microseconds; outside 1 to 999 is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn with_micros(mut self, micros: Asn1Integer) -> Result<Self, Asn1Error> {
        self.micros = Some(sub_second(micros)?);
        Ok(self)
    }

    /// Returns the seconds, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn seconds(&self) -> Option<&Asn1Integer> {
        self.seconds.as_ref()
    }

    /// Returns the milliseconds, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn millis(&self) -> Option<&Asn1Integer> {
        self.millis.as_ref()
    }

    /// Returns the microseconds, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn micros(&self) -> Option<&Asn1Integer> {
        self.micros.as_ref()
    }
}

/// `MalformedValue` outside the `(1..999)` constraint.
fn sub_second(value: Asn1Integer) -> Result<Asn1Integer, Asn1Error> {
    match u16::try_from(&value) {
        Ok(1..=999) => Ok(value),
        _ => Err(Asn1Error::MalformedValue),
    }
}

impl DecodeContent for Accuracy {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let seconds = fields.get_opt()?;
        let millis = fields
            .get_implicit_opt([0x80])?
            .map(sub_second)
            .transpose()?;
        let micros = fields
            .get_implicit_opt([0x81])?
            .map(sub_second)
            .transpose()?;
        fields.end()?;
        let value = Self {
            seconds,
            millis,
            micros,
        };
        Ok(value)
    }
}

impl DecodeInner for Accuracy {
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

impl EncodeContent for Accuracy {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.seconds.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self
                .millis
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0x80], v).encoded_len(rules))
            + self
                .micros
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0x81], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.seconds {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.millis {
            at += Implicit::new(&[0x80], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.micros {
            at += Implicit::new(&[0x81], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for Accuracy {}

impl Tagged for Accuracy {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Accuracy {}

impl Encode for Accuracy {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
