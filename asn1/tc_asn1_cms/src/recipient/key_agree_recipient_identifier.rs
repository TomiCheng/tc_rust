//! RFC 5652 §6.2.2 `KeyAgreeRecipientIdentifier`, which names a key-agreement
//! recipient's certificate.
//!
//! ```text
//! KeyAgreeRecipientIdentifier ::= CHOICE {
//!     issuerAndSerialNumber IssuerAndSerialNumber,
//!     rKeyId [0] IMPLICIT RecipientKeyIdentifier }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Implicit,
};

use crate::recipient::RecipientKeyIdentifier;
use crate::signed::IssuerAndSerialNumber;

/// The recipient's certificate, by issuer and serial number or by key
/// identifier.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum KeyAgreeRecipientIdentifier {
    /// The certificate's issuer and serial number.
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    /// `[0]`, the certificate's key identifier, with optional date and other attribute.
    RKeyId(RecipientKeyIdentifier),
}

impl From<IssuerAndSerialNumber> for KeyAgreeRecipientIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn from(value: IssuerAndSerialNumber) -> Self {
        Self::IssuerAndSerialNumber(value)
    }
}

impl From<RecipientKeyIdentifier> for KeyAgreeRecipientIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn from(value: RecipientKeyIdentifier) -> Self {
        Self::RKeyId(value)
    }
}

impl DecodeInner for KeyAgreeRecipientIdentifier {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0x30] => Self::IssuerAndSerialNumber(element.decode_as(context)?),
            [0xa0] => Self::RKeyId(RecipientKeyIdentifier::decode_content(
                element.value(),
                context,
            )?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for KeyAgreeRecipientIdentifier {}

impl EncodeContent for KeyAgreeRecipientIdentifier {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.content_len(rules),
            Self::RKeyId(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.encode_content(rules, out),
            Self::RKeyId(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for KeyAgreeRecipientIdentifier {}

impl Encode for KeyAgreeRecipientIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.encoded_len(rules),
            Self::RKeyId(inner) => Implicit::new(&[0xa0], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.encode(rules, out),
            Self::RKeyId(inner) => Implicit::new(&[0xa0], inner).encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x509::ext::SubjectKeyIdentifier;

    use super::KeyAgreeRecipientIdentifier;
    use crate::recipient::RecipientKeyIdentifier;
    use crate::signed::IssuerAndSerialNumber;

    #[test]
    fn both_alternatives_round_trip_and_the_key_identifier_is_constructed_zero() {
        let by_key = KeyAgreeRecipientIdentifier::from(RecipientKeyIdentifier::new(
            SubjectKeyIdentifier::new(alloc::vec![7; 4]).unwrap(),
        ));
        assert_eq!(
            by_key.encode_to_vec(&EncodingOptions::DER).unwrap(),
            [0xa0, 0x06, 0x04, 0x04, 7, 7, 7, 7]
        );
        let by_issuer = KeyAgreeRecipientIdentifier::from(IssuerAndSerialNumber::new(
            "CN=CA".parse().unwrap(),
            1.into(),
        ));
        for value in [by_key, by_issuer] {
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                KeyAgreeRecipientIdentifier::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
        assert_eq!(
            KeyAgreeRecipientIdentifier::decode_der(&[0x80, 0x00], &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
