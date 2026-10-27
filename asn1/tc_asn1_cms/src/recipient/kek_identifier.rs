//! RFC 5652 §6.2.3 `KEKIdentifier`, which names a previously distributed
//! key-encryption key.
//!
//! ```text
//! KEKIdentifier ::= SEQUENCE {
//!     keyIdentifier OCTET STRING,
//!     date GeneralizedTime OPTIONAL,
//!     other OtherKeyAttribute OPTIONAL }
//! ```

use crate::recipient::OtherKeyAttribute;
use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
    tag,
};

/// A shared key-encryption key, by an identifier both sides know.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct KekIdentifier {
    key_identifier: Asn1OctetString,
    date: Option<Asn1GeneralizedTime>,
    other: Option<OtherKeyAttribute>,
}

impl KekIdentifier {
    /// A key identifier without a date or other attribute.
    /// Variable time: branches only on the encoding structure.
    pub fn new(key_identifier: Asn1OctetString) -> Self {
        Self {
            key_identifier,
            date: None,
            other: None,
        }
    }

    /// Adds the date that tells keys with the same identifier apart.
    /// Variable time: branches only on the encoding structure.
    pub fn with_date(mut self, date: Asn1GeneralizedTime) -> Self {
        self.date = Some(date);
        self
    }

    /// Adds another key attribute.
    /// Variable time: branches only on the encoding structure.
    pub fn with_other(mut self, other: OtherKeyAttribute) -> Self {
        self.other = Some(other);
        self
    }

    /// Returns the key identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn key_identifier(&self) -> &Asn1OctetString {
        &self.key_identifier
    }

    /// Returns the date, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn date(&self) -> Option<&Asn1GeneralizedTime> {
        self.date.as_ref()
    }

    /// Returns the other key attribute, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn other(&self) -> Option<&OtherKeyAttribute> {
        self.other.as_ref()
    }
}

impl DecodeContent for KekIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let key_identifier = fields.get()?;
        let date = fields.get_opt()?;
        let other = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            key_identifier,
            date,
            other,
        };
        Ok(value)
    }
}

impl DecodeInner for KekIdentifier {
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

impl EncodeContent for KekIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.key_identifier.encoded_len(rules)
            + self.date.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self.other.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.key_identifier.encode(rules, out)?;
        if let Some(v) = &self.date {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.other {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for KekIdentifier {}

impl Tagged for KekIdentifier {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for KekIdentifier {}

impl Encode for KekIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{
        Asn1GeneralizedTime, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    use super::KekIdentifier;

    #[test]
    fn the_identifier_with_a_date_round_trips() {
        let value = KekIdentifier::new(Asn1OctetString::new(b"kek-1"))
            .with_date(Asn1GeneralizedTime::new(2026, 1, 1, 0, 0, 0).unwrap());
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire[2..9], [0x04, 0x05, b'k', b'e', b'k', b'-', b'1']);
        assert_eq!(
            KekIdentifier::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }
}
