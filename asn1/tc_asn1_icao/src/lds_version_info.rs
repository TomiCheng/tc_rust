//! ICAO Doc 9303 part 10 `LDSVersionInfo`, the LDS and Unicode versions of a
//! document.
//!
//! ```text
//! LDSVersionInfo ::= SEQUENCE {
//!     ldsVersion     PRINTABLE STRING,
//!     unicodeVersion PRINTABLE STRING }
//! ```

use tc_asn1::{
    Asn1Error, Asn1PrintableString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The version of the logical data structure and of Unicode it uses.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct LdsVersionInfo {
    lds_version: Asn1PrintableString,
    unicode_version: Asn1PrintableString,
}

impl LdsVersionInfo {
    /// Both versions.
    /// Variable time: branches only on the encoding structure.
    pub fn new(lds_version: Asn1PrintableString, unicode_version: Asn1PrintableString) -> Self {
        Self {
            lds_version,
            unicode_version,
        }
    }

    /// Returns the LDS version, such as "0108".
    /// Variable time: branches only on the encoding structure.
    pub fn lds_version(&self) -> &Asn1PrintableString {
        &self.lds_version
    }

    /// Returns the Unicode version, such as "040000".
    /// Variable time: branches only on the encoding structure.
    pub fn unicode_version(&self) -> &Asn1PrintableString {
        &self.unicode_version
    }
}

impl DecodeContent for LdsVersionInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let lds_version = fields.get()?;
        let unicode_version = fields.get()?;
        fields.end()?;
        let value = Self {
            lds_version,
            unicode_version,
        };
        Ok(value)
    }
}

impl DecodeInner for LdsVersionInfo {
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

impl EncodeContent for LdsVersionInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.lds_version.encoded_len(rules) + self.unicode_version.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.lds_version.encode(rules, out)?;
        at += self.unicode_version.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for LdsVersionInfo {}

impl Tagged for LdsVersionInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for LdsVersionInfo {}

impl Encode for LdsVersionInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
