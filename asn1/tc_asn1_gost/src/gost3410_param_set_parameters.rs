//! The parameters of GOST R 34.10-94, as Bouncy Castle's
//! `Gost3410ParamSetParameters` writes them.
//!
//! ```text
//! Gost3410ParamSetParameters ::= SEQUENCE {
//!     keySize INTEGER,
//!     p       INTEGER,
//!     q       INTEGER,
//!     a       INTEGER }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The key size, the primes `p` and `q`, and the generator `a`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Gost3410ParamSetParameters {
    key_size: Asn1Integer,
    p: Asn1Integer,
    q: Asn1Integer,
    a: Asn1Integer,
}

impl Gost3410ParamSetParameters {
    /// Every parameter.
    /// Variable time: branches only on the encoding structure.
    pub fn new(key_size: Asn1Integer, p: Asn1Integer, q: Asn1Integer, a: Asn1Integer) -> Self {
        Self { key_size, p, q, a }
    }

    /// Returns the key size in bits.
    /// Variable time: branches only on the encoding structure.
    pub fn key_size(&self) -> &Asn1Integer {
        &self.key_size
    }

    /// Returns the prime modulus.
    /// Variable time: branches only on the encoding structure.
    pub fn p(&self) -> &Asn1Integer {
        &self.p
    }

    /// Returns the prime order.
    /// Variable time: branches only on the encoding structure.
    pub fn q(&self) -> &Asn1Integer {
        &self.q
    }

    /// Returns the generator.
    /// Variable time: branches only on the encoding structure.
    pub fn a(&self) -> &Asn1Integer {
        &self.a
    }
}

impl DecodeContent for Gost3410ParamSetParameters {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let key_size = fields.get()?;
        let p = fields.get()?;
        let q = fields.get()?;
        let a = fields.get()?;
        fields.end()?;
        let value = Self { key_size, p, q, a };
        Ok(value)
    }
}

impl DecodeInner for Gost3410ParamSetParameters {
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

impl EncodeContent for Gost3410ParamSetParameters {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.key_size.encoded_len(rules)
            + self.p.encoded_len(rules)
            + self.q.encoded_len(rules)
            + self.a.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.key_size.encode(rules, out)?;
        at += self.p.encode(rules, &mut out[at..])?;
        at += self.q.encode(rules, &mut out[at..])?;
        at += self.a.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for Gost3410ParamSetParameters {}

impl Tagged for Gost3410ParamSetParameters {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Gost3410ParamSetParameters {}

impl Encode for Gost3410ParamSetParameters {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
