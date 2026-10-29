//! RFC 4210 §5.1.1 `PKIFreeText`, human-readable text with language tags.
//!
//! ```text
//! PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Asn1Utf8String, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// One or more strings, each optionally led by an RFC 3066 language tag.
///
/// ```
/// use tc_asn1::{Asn1Utf8String, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cmp::PkiFreeText;
///
/// let text = PkiFreeText::new(vec![Asn1Utf8String::new("bad request")])?;
/// let der = text.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(PkiFreeText::decode_der(&der, &DecodingOptions::default())?.1, text);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PkiFreeText {
    strings: Asn1SequenceOf<Asn1Utf8String>,
}

impl PkiFreeText {
    /// The strings, in order. None is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(strings: Vec<Asn1Utf8String>) -> Result<Self, Asn1Error> {
        if strings.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            strings: Asn1SequenceOf::new(strings),
        })
    }

    /// Returns the strings in order.
    /// Variable time: branches only on the encoding structure.
    pub fn strings(&self) -> &[Asn1Utf8String] {
        self.strings.elements()
    }
}

impl DecodeContent for PkiFreeText {
    /// An empty sequence is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let strings = Asn1SequenceOf::decode_content(value, context)?;
        if strings.elements().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { strings })
    }
}

impl DecodeInner for PkiFreeText {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, strings) = Asn1SequenceOf::<Asn1Utf8String>::decode_inner(buff, context)?;
        if strings.elements().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((len, Self { strings }))
    }
}

impl EncodeContent for PkiFreeText {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.strings.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.strings.encode_content(rules, out)
    }
}

impl Decode for PkiFreeText {}

impl Tagged for PkiFreeText {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PkiFreeText {}

impl Encode for PkiFreeText {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
