//! Common PKI `MonetaryLimitSyntax`, the value of the monetaryLimit attribute.
//!
//! ```text
//! MonetaryLimitSyntax ::= SEQUENCE {
//!     currency PrintableString (SIZE(3)),
//!     amount   INTEGER,
//!     exponent INTEGER }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1PrintableString, Asn1Ref, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
    tag,
};

/// A limit of `amount * 10^exponent` in an ISO 4217 currency.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MonetaryLimit {
    currency: Asn1PrintableString,
    amount: Asn1Integer,
    exponent: Asn1Integer,
}

impl MonetaryLimit {
    /// The currency, amount and exponent.
    /// Variable time: branches only on the encoding structure.
    pub fn new(currency: Asn1PrintableString, amount: Asn1Integer, exponent: Asn1Integer) -> Self {
        Self {
            currency,
            amount,
            exponent,
        }
    }

    /// Returns the ISO 4217 currency code.
    /// Variable time: branches only on the encoding structure.
    pub fn currency(&self) -> &Asn1PrintableString {
        &self.currency
    }

    /// Returns the amount.
    /// Variable time: branches only on the encoding structure.
    pub fn amount(&self) -> &Asn1Integer {
        &self.amount
    }

    /// Returns the power of ten the amount is scaled by.
    /// Variable time: branches only on the encoding structure.
    pub fn exponent(&self) -> &Asn1Integer {
        &self.exponent
    }
}

impl DecodeContent for MonetaryLimit {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let currency = fields.get()?;
        let amount = fields.get()?;
        let exponent = fields.get()?;
        fields.end()?;
        let value = Self {
            currency,
            amount,
            exponent,
        };
        Ok(value)
    }
}

impl DecodeInner for MonetaryLimit {
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

impl EncodeContent for MonetaryLimit {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.currency.encoded_len(rules)
            + self.amount.encoded_len(rules)
            + self.exponent.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.currency.encode(rules, out)?;
        at += self.amount.encode(rules, &mut out[at..])?;
        at += self.exponent.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for MonetaryLimit {}

impl Tagged for MonetaryLimit {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for MonetaryLimit {}

impl Encode for MonetaryLimit {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
