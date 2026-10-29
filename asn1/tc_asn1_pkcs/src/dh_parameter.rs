//! PKCS #3 `DHParameter`, the Diffie-Hellman group of the PKCS #3 key-agreement
//! algorithm.
//!
//! ```text
//! DHParameter ::= SEQUENCE {
//!     prime              INTEGER, -- p
//!     base               INTEGER, -- g
//!     privateValueLength INTEGER OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A prime, a base and an optional private-value length in bits.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DhParameter {
    p: Asn1Integer,
    g: Asn1Integer,
    l: Option<Asn1Integer>,
}

impl DhParameter {
    /// The prime and base, without a private-value length.
    /// Variable time: branches only on the encoding structure.
    pub fn new(p: Asn1Integer, g: Asn1Integer) -> Self {
        Self { p, g, l: None }
    }

    /// Adds the private-value length in bits.
    /// Variable time: branches only on the encoding structure.
    pub fn with_l(mut self, l: Asn1Integer) -> Self {
        self.l = Some(l);
        self
    }

    /// Returns the prime p.
    /// Variable time: branches only on the encoding structure.
    pub fn p(&self) -> &Asn1Integer {
        &self.p
    }

    /// Returns the base g.
    /// Variable time: branches only on the encoding structure.
    pub fn g(&self) -> &Asn1Integer {
        &self.g
    }

    /// Returns the private-value length in bits, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn l(&self) -> Option<&Asn1Integer> {
        self.l.as_ref()
    }
}

impl DecodeContent for DhParameter {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let p = fields.get()?;
        let g = fields.get()?;
        let l = fields.get_opt()?;
        fields.end()?;
        let value = Self { p, g, l };
        Ok(value)
    }
}

impl DecodeInner for DhParameter {
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

impl EncodeContent for DhParameter {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.p.encoded_len(rules)
            + self.g.encoded_len(rules)
            + self.l.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.p.encode(rules, out)?;
        at += self.g.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.l {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for DhParameter {}

impl Tagged for DhParameter {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for DhParameter {}

impl Encode for DhParameter {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
