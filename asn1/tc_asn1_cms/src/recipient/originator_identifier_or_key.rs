//! RFC 5652 §6.2.2 `OriginatorIdentifierOrKey`, the sender's side of a key
//! agreement.
//!
//! ```text
//! OriginatorIdentifierOrKey ::= CHOICE {
//!     issuerAndSerialNumber IssuerAndSerialNumber,
//!     subjectKeyIdentifier [0] SubjectKeyIdentifier,   -- IMPLICIT
//!     originatorKey [1] OriginatorPublicKey }           -- IMPLICIT
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Implicit,
};
use tc_asn1_x509::ext::SubjectKeyIdentifier;

use crate::recipient::OriginatorPublicKey;
use crate::signed::IssuerAndSerialNumber;

/// The originator's static certificate, or its ephemeral public key.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum OriginatorIdentifierOrKey {
    /// The certificate's issuer and serial number.
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    /// `[0]`, the certificate's subject key identifier.
    SubjectKeyIdentifier(SubjectKeyIdentifier),
    /// `[1]`, the originator's public key itself, as in ephemeral-static ECDH.
    OriginatorKey(OriginatorPublicKey),
}

impl From<IssuerAndSerialNumber> for OriginatorIdentifierOrKey {
    /// Variable time: branches only on the encoding structure.
    fn from(value: IssuerAndSerialNumber) -> Self {
        Self::IssuerAndSerialNumber(value)
    }
}

impl From<SubjectKeyIdentifier> for OriginatorIdentifierOrKey {
    /// Variable time: branches only on the encoding structure.
    fn from(value: SubjectKeyIdentifier) -> Self {
        Self::SubjectKeyIdentifier(value)
    }
}

impl From<OriginatorPublicKey> for OriginatorIdentifierOrKey {
    /// Variable time: branches only on the encoding structure.
    fn from(value: OriginatorPublicKey) -> Self {
        Self::OriginatorKey(value)
    }
}

impl DecodeInner for OriginatorIdentifierOrKey {
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
            [0xa1] => Self::OriginatorKey(OriginatorPublicKey::decode_content(
                element.value(),
                context,
            )?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for OriginatorIdentifierOrKey {}

impl EncodeContent for OriginatorIdentifierOrKey {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.content_len(rules),
            Self::SubjectKeyIdentifier(inner) => inner.content_len(rules),
            Self::OriginatorKey(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.encode_content(rules, out),
            Self::SubjectKeyIdentifier(inner) => inner.encode_content(rules, out),
            Self::OriginatorKey(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for OriginatorIdentifierOrKey {}

impl Encode for OriginatorIdentifierOrKey {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.encoded_len(rules),
            Self::SubjectKeyIdentifier(inner) => Implicit::new(&[0x80], inner).encoded_len(rules),
            Self::OriginatorKey(inner) => Implicit::new(&[0xa1], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::IssuerAndSerialNumber(inner) => inner.encode(rules, out),
            Self::SubjectKeyIdentifier(inner) => Implicit::new(&[0x80], inner).encode(rules, out),
            Self::OriginatorKey(inner) => Implicit::new(&[0xa1], inner).encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1BitString, Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x509::ext::SubjectKeyIdentifier;

    use super::OriginatorIdentifierOrKey;
    use crate::fixtures::alg;
    use crate::recipient::OriginatorPublicKey;
    use crate::signed::IssuerAndSerialNumber;

    #[test]
    fn all_three_alternatives_round_trip_under_their_identifiers() {
        let key = OriginatorPublicKey::new(
            alg("1.2.840.10045.2.1"),
            Asn1BitString::from_bytes(&[4, 1, 2]),
        );
        for (value, first) in [
            (
                OriginatorIdentifierOrKey::from(IssuerAndSerialNumber::new(
                    "CN=CA".parse().unwrap(),
                    1.into(),
                )),
                0x30,
            ),
            (
                SubjectKeyIdentifier::new(alloc::vec![7; 4]).unwrap().into(),
                0x80,
            ),
            (key.into(), 0xa1),
        ] {
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(wire[0], first);
            assert_eq!(
                OriginatorIdentifierOrKey::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
        assert_eq!(
            OriginatorIdentifierOrKey::decode_der(&[0xa2, 0x00], &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
