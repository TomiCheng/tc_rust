//! DSTU 4145 `BinaryField`, the field `GF(2^m)` of a curve.
//!
//! ```text
//! BinaryField ::= SEQUENCE {
//!     M INTEGER,
//!     CHOICE { Trinomial, Pentanomial } }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::Dstu4145Exponents;

/// The degree `m` and the reduction polynomial.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Dstu4145BinaryField {
    m: Asn1Integer,
    exponents: Dstu4145Exponents,
}

impl Dstu4145BinaryField {
    /// The degree and the polynomial.
    /// Variable time: branches only on the encoding structure.
    pub fn new(m: Asn1Integer, exponents: Dstu4145Exponents) -> Self {
        Self { m, exponents }
    }

    /// Returns the degree of the field.
    /// Variable time: branches only on the encoding structure.
    pub fn m(&self) -> &Asn1Integer {
        &self.m
    }

    /// Returns the reduction polynomial.
    /// Variable time: branches only on the encoding structure.
    pub fn exponents(&self) -> &Dstu4145Exponents {
        &self.exponents
    }
}

impl DecodeContent for Dstu4145BinaryField {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let m = fields.get()?;
        let exponents = fields.get()?;
        fields.end()?;
        let value = Self { m, exponents };
        Ok(value)
    }
}

impl DecodeInner for Dstu4145BinaryField {
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

impl EncodeContent for Dstu4145BinaryField {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.m.encoded_len(rules) + self.exponents.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.m.encode(rules, out)?;
        at += self.exponents.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for Dstu4145BinaryField {}

impl Tagged for Dstu4145BinaryField {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Dstu4145BinaryField {}

impl Encode for Dstu4145BinaryField {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
