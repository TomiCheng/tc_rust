//! The pentanomial basis of a DSTU 4145 binary field.
//!
//! ```text
//! Pentanomial ::= SEQUENCE {
//!     k INTEGER,
//!     j INTEGER,
//!     l INTEGER }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The exponents of `x^m + x^k + x^j + x^l + 1`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Dstu4145Pentanomial {
    k: Asn1Integer,
    j: Asn1Integer,
    l: Asn1Integer,
}

impl Dstu4145Pentanomial {
    /// The three middle exponents.
    /// Variable time: branches only on the encoding structure.
    pub fn new(k: Asn1Integer, j: Asn1Integer, l: Asn1Integer) -> Self {
        Self { k, j, l }
    }

    /// Returns the exponent `k`.
    /// Variable time: branches only on the encoding structure.
    pub fn k(&self) -> &Asn1Integer {
        &self.k
    }

    /// Returns the exponent `j`.
    /// Variable time: branches only on the encoding structure.
    pub fn j(&self) -> &Asn1Integer {
        &self.j
    }

    /// Returns the exponent `l`.
    /// Variable time: branches only on the encoding structure.
    pub fn l(&self) -> &Asn1Integer {
        &self.l
    }
}

impl DecodeContent for Dstu4145Pentanomial {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let k = fields.get()?;
        let j = fields.get()?;
        let l = fields.get()?;
        fields.end()?;
        let value = Self { k, j, l };
        Ok(value)
    }
}

impl DecodeInner for Dstu4145Pentanomial {
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

impl EncodeContent for Dstu4145Pentanomial {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.k.encoded_len(rules) + self.j.encoded_len(rules) + self.l.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.k.encode(rules, out)?;
        at += self.j.encode(rules, &mut out[at..])?;
        at += self.l.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for Dstu4145Pentanomial {}

impl Tagged for Dstu4145Pentanomial {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Dstu4145Pentanomial {}

impl Encode for Dstu4145Pentanomial {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
