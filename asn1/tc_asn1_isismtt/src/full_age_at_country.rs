//! Common PKI `fullAgeAtCountry`, majority under a country's law.
//!
//! ```text
//! SEQUENCE {
//!     fullAge BOOLEAN DEFAULT TRUE,
//!     country PrintableString (SIZE(2)) }
//! ```
//!
//! A written default `fullAge` is accepted under BER and rejected under DER;
//! encoding omits it.

use tc_asn1::{
    Asn1Boolean, Asn1Error, Asn1PrintableString, Asn1Ref, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
    tag,
};

/// Whether the holder is of full age in a country.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct FullAgeAtCountry {
    full_age: Asn1Boolean,
    country: Asn1PrintableString,
}

impl FullAgeAtCountry {
    /// Full age in this country.
    /// Variable time: branches only on the encoding structure.
    pub fn new(country: Asn1PrintableString) -> Self {
        Self {
            full_age: Asn1Boolean::from(true),
            country,
        }
    }

    /// Sets whether the holder is of full age.
    /// Variable time: branches only on the encoding structure.
    pub fn with_full_age(mut self, full_age: Asn1Boolean) -> Self {
        self.full_age = full_age;
        self
    }

    /// Returns whether the holder is of full age.
    /// Variable time: branches only on the encoding structure.
    pub fn full_age(&self) -> &Asn1Boolean {
        &self.full_age
    }

    /// Returns the ISO 3166 country code.
    /// Variable time: branches only on the encoding structure.
    pub fn country(&self) -> &Asn1PrintableString {
        &self.country
    }
}

impl DecodeContent for FullAgeAtCountry {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let full_age = fields.get_default(Asn1Boolean::from(true))?;
        let country = fields.get()?;
        fields.end()?;
        let value = Self { full_age, country };
        Ok(value)
    }
}

impl DecodeInner for FullAgeAtCountry {
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

impl EncodeContent for FullAgeAtCountry {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        (if self.full_age != Asn1Boolean::from(true) {
            self.full_age.encoded_len(rules)
        } else {
            0
        }) + self.country.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if self.full_age != Asn1Boolean::from(true) {
            at += self.full_age.encode(rules, &mut out[at..])?;
        }
        at += self.country.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for FullAgeAtCountry {}

impl Tagged for FullAgeAtCountry {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for FullAgeAtCountry {}

impl Encode for FullAgeAtCountry {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
