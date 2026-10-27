//! RFC 5652 §6.2.2 `RecipientKeyIdentifier`, a key-agreement recipient's key
//! identifier with an optional date and other attribute.
//!
//! ```text
//! RecipientKeyIdentifier ::= SEQUENCE {
//!     subjectKeyIdentifier SubjectKeyIdentifier,
//!     date GeneralizedTime OPTIONAL,
//!     other OtherKeyAttribute OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::ext::SubjectKeyIdentifier;

use crate::recipient::OtherKeyAttribute;

/// A recipient key, by its subject key identifier.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RecipientKeyIdentifier {
    subject_key_identifier: SubjectKeyIdentifier,
    date: Option<Asn1GeneralizedTime>,
    other: Option<OtherKeyAttribute>,
}

impl RecipientKeyIdentifier {
    /// A key identifier without a date or other attribute.
    /// Variable time: branches only on the encoding structure.
    pub fn new(subject_key_identifier: SubjectKeyIdentifier) -> Self {
        Self {
            subject_key_identifier,
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

    /// Returns the subject key identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn subject_key_identifier(&self) -> &SubjectKeyIdentifier {
        &self.subject_key_identifier
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

impl DecodeContent for RecipientKeyIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let subject_key_identifier = fields.get()?;
        let date = fields.get_opt()?;
        let other = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            subject_key_identifier,
            date,
            other,
        };
        Ok(value)
    }
}

impl DecodeInner for RecipientKeyIdentifier {
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

impl EncodeContent for RecipientKeyIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.subject_key_identifier.encoded_len(rules)
            + self.date.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self.other.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.subject_key_identifier.encode(rules, out)?;
        if let Some(v) = &self.date {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.other {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for RecipientKeyIdentifier {}

impl Tagged for RecipientKeyIdentifier {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RecipientKeyIdentifier {}

impl Encode for RecipientKeyIdentifier {
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
        Asn1Error, Asn1GeneralizedTime, Decode, DecodingOptions, Encode, EncodingOptions,
    };
    use tc_asn1_x509::ext::SubjectKeyIdentifier;

    use super::RecipientKeyIdentifier;
    use crate::recipient::OtherKeyAttribute;

    #[test]
    fn every_combination_of_date_and_other_attribute_round_trips() {
        let base =
            || RecipientKeyIdentifier::new(SubjectKeyIdentifier::new(alloc::vec![5; 8]).unwrap());
        let date = Asn1GeneralizedTime::new(2026, 10, 27, 0, 0, 0).unwrap();
        let other = OtherKeyAttribute::new("1.2.3".parse().unwrap());
        for value in [
            base(),
            base().with_date(date),
            base().with_other(other.clone()),
            base().with_date(date).with_other(other),
        ] {
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                RecipientKeyIdentifier::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn the_other_attribute_before_the_date_is_rejected() {
        let wire = [
            0x30, 0x1a, 0x04, 0x01, 0x05, 0x30, 0x04, 0x06, 0x02, 0x2a, 0x03, 0x18, 0x0f, b'2',
            b'0', b'2', b'6', b'1', b'0', b'2', b'7', b'0', b'0', b'0', b'0', b'0', b'0', b'Z',
        ];
        assert_eq!(
            RecipientKeyIdentifier::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }
}
