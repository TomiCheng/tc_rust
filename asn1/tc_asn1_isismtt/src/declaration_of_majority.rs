//! Common PKI `DeclarationOfMajoritySyntax`, the value of the declarationOfMajority
//! attribute.
//!
//! ```text
//! DeclarationOfMajoritySyntax ::= CHOICE {
//!     notYoungerThan   [0] IMPLICIT INTEGER,
//!     fullAgeAtCountry [1] IMPLICIT SEQUENCE {
//!         fullAge BOOLEAN DEFAULT TRUE,
//!         country PrintableString (SIZE(2)) },
//!     dateOfBirth      [2] IMPLICIT GeneralizedTime }
//! ```

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Integer, Asn1Ref, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit,
};

use crate::FullAgeAtCountry;

/// A minimum age, full age in a country, or the date of birth.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum DeclarationOfMajority {
    /// `[0]`, the holder is at least this old.
    NotYoungerThan(Asn1Integer),
    /// `[1]`, full age in a country.
    FullAgeAtCountry(FullAgeAtCountry),
    /// `[2]`, the date of birth.
    DateOfBirth(Asn1GeneralizedTime),
}

impl DecodeInner for DeclarationOfMajority {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0x80] => {
                Self::NotYoungerThan(DecodeContent::decode_content(element.value(), context)?)
            }
            [0xa1] => {
                Self::FullAgeAtCountry(DecodeContent::decode_content(element.value(), context)?)
            }
            [0x82] => Self::DateOfBirth(DecodeContent::decode_content(element.value(), context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for DeclarationOfMajority {}

impl EncodeContent for DeclarationOfMajority {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::NotYoungerThan(inner) => inner.content_len(rules),
            Self::FullAgeAtCountry(inner) => inner.content_len(rules),
            Self::DateOfBirth(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::NotYoungerThan(inner) => inner.encode_content(rules, out),
            Self::FullAgeAtCountry(inner) => inner.encode_content(rules, out),
            Self::DateOfBirth(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for DeclarationOfMajority {}

impl Encode for DeclarationOfMajority {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::NotYoungerThan(inner) => Implicit::new(&[0x80], inner).encoded_len(rules),
            Self::FullAgeAtCountry(inner) => Implicit::new(&[0xa1], inner).encoded_len(rules),
            Self::DateOfBirth(inner) => Implicit::new(&[0x82], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::NotYoungerThan(inner) => Implicit::new(&[0x80], inner).encode(rules, out),
            Self::FullAgeAtCountry(inner) => Implicit::new(&[0xa1], inner).encode(rules, out),
            Self::DateOfBirth(inner) => Implicit::new(&[0x82], inner).encode(rules, out),
        }
    }
}
