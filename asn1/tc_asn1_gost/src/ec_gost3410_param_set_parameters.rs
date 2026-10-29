//! The parameters of a GOST R 34.10-2001 elliptic curve, as Bouncy Castle's
//! `ECGost3410ParamSetParameters` writes them.
//!
//! ```text
//! ECGost3410ParamSetParameters ::= SEQUENCE {
//!     a INTEGER,
//!     b INTEGER,
//!     p INTEGER,
//!     q INTEGER,
//!     x INTEGER,
//!     y INTEGER }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The curve `y^2 = x^3 + ax + b` over the prime `p`, and a base point `(x, y)` of
/// order `q`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EcGost3410ParamSetParameters {
    a: Asn1Integer,
    b: Asn1Integer,
    p: Asn1Integer,
    q: Asn1Integer,
    x: Asn1Integer,
    y: Asn1Integer,
}

impl EcGost3410ParamSetParameters {
    /// Every parameter.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        a: Asn1Integer,
        b: Asn1Integer,
        p: Asn1Integer,
        q: Asn1Integer,
        x: Asn1Integer,
        y: Asn1Integer,
    ) -> Self {
        Self { a, b, p, q, x, y }
    }

    /// Returns the coefficient `a`.
    /// Variable time: branches only on the encoding structure.
    pub fn a(&self) -> &Asn1Integer {
        &self.a
    }

    /// Returns the coefficient `b`.
    /// Variable time: branches only on the encoding structure.
    pub fn b(&self) -> &Asn1Integer {
        &self.b
    }

    /// Returns the field prime.
    /// Variable time: branches only on the encoding structure.
    pub fn p(&self) -> &Asn1Integer {
        &self.p
    }

    /// Returns the order of the base point.
    /// Variable time: branches only on the encoding structure.
    pub fn q(&self) -> &Asn1Integer {
        &self.q
    }

    /// Returns the x coordinate of the base point.
    /// Variable time: branches only on the encoding structure.
    pub fn x(&self) -> &Asn1Integer {
        &self.x
    }

    /// Returns the y coordinate of the base point.
    /// Variable time: branches only on the encoding structure.
    pub fn y(&self) -> &Asn1Integer {
        &self.y
    }
}

impl DecodeContent for EcGost3410ParamSetParameters {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let a = fields.get()?;
        let b = fields.get()?;
        let p = fields.get()?;
        let q = fields.get()?;
        let x = fields.get()?;
        let y = fields.get()?;
        fields.end()?;
        let value = Self { a, b, p, q, x, y };
        Ok(value)
    }
}

impl DecodeInner for EcGost3410ParamSetParameters {
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

impl EncodeContent for EcGost3410ParamSetParameters {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.a.encoded_len(rules)
            + self.b.encoded_len(rules)
            + self.p.encoded_len(rules)
            + self.q.encoded_len(rules)
            + self.x.encoded_len(rules)
            + self.y.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.a.encode(rules, out)?;
        at += self.b.encode(rules, &mut out[at..])?;
        at += self.p.encode(rules, &mut out[at..])?;
        at += self.q.encode(rules, &mut out[at..])?;
        at += self.x.encode(rules, &mut out[at..])?;
        at += self.y.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for EcGost3410ParamSetParameters {}

impl Tagged for EcGost3410ParamSetParameters {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EcGost3410ParamSetParameters {}

impl Encode for EcGost3410ParamSetParameters {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
