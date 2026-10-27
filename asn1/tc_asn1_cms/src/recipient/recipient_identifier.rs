//! RFC 5652 §6.2.1 `RecipientIdentifier`, which names the certificate a
//! key-transport recipient's key is in.
//!
//! ```text
//! RecipientIdentifier ::= CHOICE {
//!     issuerAndSerialNumber IssuerAndSerialNumber,
//!     subjectKeyIdentifier [0] SubjectKeyIdentifier }   -- IMPLICIT
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Implicit,
};
use tc_asn1_x509::ext::SubjectKeyIdentifier;

use crate::signed::IssuerAndSerialNumber;

/// The recipient's certificate, by issuer and serial number or by key identifier.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum RecipientIdentifier {
    /// The certificate's issuer and serial number; the recipient is then version 0.
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    /// `[0]`, the certificate's subject key identifier; the recipient is then version 2.
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

impl From<IssuerAndSerialNumber> for RecipientIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn from(value: IssuerAndSerialNumber) -> Self {
        Self::IssuerAndSerialNumber(value)
    }
}

impl From<SubjectKeyIdentifier> for RecipientIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn from(value: SubjectKeyIdentifier) -> Self {
        Self::SubjectKeyIdentifier(value)
    }
}

impl DecodeInner for RecipientIdentifier {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0x30] => Self::IssuerAndSerialNumber(element.decode_as(context)?),
            [0x80] => Self::SubjectKeyIdentifier(SubjectKeyIdentifier::decode_content(
                element.value(),
                context,
            )?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for RecipientIdentifier {}

impl EncodeContent for RecipientIdentifier {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.content_len(rules),
            Self::SubjectKeyIdentifier(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.encode_content(rules, out),
            Self::SubjectKeyIdentifier(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for RecipientIdentifier {}

impl Encode for RecipientIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.encoded_len(rules),
            Self::SubjectKeyIdentifier(inner) => Implicit::new(&[0x80], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.encode(rules, out),
            Self::SubjectKeyIdentifier(inner) => Implicit::new(&[0x80], inner).encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x509::ext::SubjectKeyIdentifier;

    use super::RecipientIdentifier;
    use crate::signed::IssuerAndSerialNumber;

    #[test]
    fn both_alternatives_round_trip_and_the_key_identifier_is_primitive_zero() {
        let by_key =
            RecipientIdentifier::from(SubjectKeyIdentifier::new(alloc::vec![1, 2, 3]).unwrap());
        assert_eq!(
            by_key.encode_to_vec(&EncodingOptions::DER).unwrap(),
            [0x80, 0x03, 1, 2, 3]
        );
        let by_issuer = RecipientIdentifier::from(IssuerAndSerialNumber::new(
            "CN=CA".parse().unwrap(),
            7.into(),
        ));
        for value in [by_key, by_issuer] {
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                RecipientIdentifier::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
        assert_eq!(
            RecipientIdentifier::decode_der(b"\x81\x01\x01", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
