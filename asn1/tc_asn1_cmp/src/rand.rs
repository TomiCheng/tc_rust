//! RFC 4210 §5.2.8 `Rand`, what a POP challenge encrypts.
//!
//! ```text
//! Rand ::= SEQUENCE {
//!     int    INTEGER,
//!     sender GeneralName }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::name::GeneralName;

/// A random integer and the sender's name; Bouncy Castle's `Challenge.Rand`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Rand {
    int: Asn1Integer,
    sender: GeneralName,
}

impl Rand {
    /// The integer and the sender.
    /// Variable time: branches only on the encoding structure.
    pub fn new(int: Asn1Integer, sender: GeneralName) -> Self {
        Self { int, sender }
    }

    /// Returns the random integer.
    /// Variable time: branches only on the encoding structure.
    pub fn int(&self) -> &Asn1Integer {
        &self.int
    }

    /// Returns the sender, as in the header.
    /// Variable time: branches only on the encoding structure.
    pub fn sender(&self) -> &GeneralName {
        &self.sender
    }
}

impl DecodeContent for Rand {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let int = fields.get()?;
        let sender = fields.get()?;
        fields.end()?;
        let value = Self { int, sender };
        Ok(value)
    }
}

impl DecodeInner for Rand {
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

impl EncodeContent for Rand {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.int.encoded_len(rules) + self.sender.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.int.encode(rules, out)?;
        at += self.sender.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for Rand {}

impl Tagged for Rand {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Rand {}

impl Encode for Rand {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
