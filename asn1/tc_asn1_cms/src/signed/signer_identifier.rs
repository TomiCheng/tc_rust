//! RFC 5652 §5.3 `SignerIdentifier`, which names the certificate a signer used.
//!
//! ```text
//! SignerIdentifier ::= CHOICE {
//!     issuerAndSerialNumber IssuerAndSerialNumber,
//!     subjectKeyIdentifier [0] SubjectKeyIdentifier }   -- IMPLICIT
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Implicit,
};
use tc_asn1_x509::ext::SubjectKeyIdentifier;

use crate::signed::IssuerAndSerialNumber;

/// The signer's certificate, by issuer and serial number or by key identifier.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SignerIdentifier {
    /// The certificate's issuer and serial number; the signer is then version 1.
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    /// `[0]`, the certificate's subject key identifier; the signer is then version 3.
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

impl From<IssuerAndSerialNumber> for SignerIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn from(value: IssuerAndSerialNumber) -> Self {
        Self::IssuerAndSerialNumber(value)
    }
}

impl From<SubjectKeyIdentifier> for SignerIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn from(value: SubjectKeyIdentifier) -> Self {
        Self::SubjectKeyIdentifier(value)
    }
}

impl DecodeInner for SignerIdentifier {
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

impl Decode for SignerIdentifier {}

impl EncodeContent for SignerIdentifier {
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

impl EncodeTagged for SignerIdentifier {}

impl Encode for SignerIdentifier {
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

    use super::SignerIdentifier;
    use crate::signed::IssuerAndSerialNumber;

    #[test]
    fn a_key_identifier_goes_under_a_primitive_context_zero() {
        let value =
            SignerIdentifier::from(SubjectKeyIdentifier::new(alloc::vec![1, 2, 3]).unwrap());
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire, [0x80, 0x03, 1, 2, 3]);
        assert_eq!(
            SignerIdentifier::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn an_issuer_and_serial_number_is_the_untagged_alternative() {
        let value = SignerIdentifier::from(IssuerAndSerialNumber::new(
            "CN=CA".parse().unwrap(),
            7.into(),
        ));
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire[0], 0x30);
        assert_eq!(
            SignerIdentifier::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn empty_key_identifiers_and_other_identifiers_are_rejected() {
        for (wire, error) in [
            (&b"\x80\x00"[..], Asn1Error::MalformedValue),
            (&b"\x04\x01\x01"[..], Asn1Error::UnexpectedTag),
            (&b"\x81\x01\x01"[..], Asn1Error::UnexpectedTag),
        ] {
            assert_eq!(
                SignerIdentifier::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
