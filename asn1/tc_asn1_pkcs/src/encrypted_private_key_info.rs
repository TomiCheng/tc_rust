//! RFC 5958 §3 encrypted private-key containers.
//!
//! ```text
//! EncryptedPrivateKeyInfo ::= SEQUENCE {
//!     encryptionAlgorithm AlgorithmIdentifier,
//!     encryptedData       OCTET STRING }
//! ```
//!
//! The octets are ciphertext. This crate neither decrypts them nor recognises
//! the encryption scheme; algorithm parameters and ciphertext remain opaque.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::AlgorithmIdentifier;

/// An encryption algorithm and its uninterpreted ciphertext.
///
/// ```
/// use tc_asn1::Asn1OctetString;
/// use tc_asn1_pkcs::EncryptedPrivateKeyInfo;
/// use tc_asn1_x509::AlgorithmIdentifier;
///
/// let info = EncryptedPrivateKeyInfo::new(
///     AlgorithmIdentifier::new("1.2.840.113549.1.5.13".parse()?),
///     Asn1OctetString::new(&[0xab, 0xcd]),
/// );
/// assert_eq!(info.encrypted_data().as_bytes(), &[0xab, 0xcd]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EncryptedPrivateKeyInfo {
    encryption_algorithm: AlgorithmIdentifier,
    encrypted_data: Asn1OctetString,
}

impl EncryptedPrivateKeyInfo {
    /// Stores the algorithm and ciphertext without interpreting either.
    /// Variable time: branches only on the encoding structure.
    pub fn new(encryption_algorithm: AlgorithmIdentifier, encrypted_data: Asn1OctetString) -> Self {
        Self {
            encryption_algorithm,
            encrypted_data,
        }
    }

    /// Returns the encryption algorithm and its parameters.
    /// Variable time: branches only on the encoding structure.
    pub fn encryption_algorithm(&self) -> &AlgorithmIdentifier {
        &self.encryption_algorithm
    }

    /// Returns the ciphertext.
    /// Variable time: branches only on the encoding structure.
    pub fn encrypted_data(&self) -> &Asn1OctetString {
        &self.encrypted_data
    }
}

impl fmt::Display for EncryptedPrivateKeyInfo {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, {} ciphertext octets",
            self.encryption_algorithm,
            self.encrypted_data.as_bytes().len()
        )
    }
}

impl DecodeInner for EncryptedPrivateKeyInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let algorithm = fields.get()?;
        let ciphertext = fields.get()?;
        fields.end()?;
        Ok((element.total_len(), Self::new(algorithm, ciphertext)))
    }
}

impl EncodeContent for EncryptedPrivateKeyInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.encryption_algorithm.encoded_len(rules) + self.encrypted_data.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        at += self.encryption_algorithm.encode(rules, &mut out[at..])?;
        at += self.encrypted_data.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for EncryptedPrivateKeyInfo {}

impl Tagged for EncryptedPrivateKeyInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EncryptedPrivateKeyInfo {}

impl Encode for EncryptedPrivateKeyInfo {
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
    use alloc::string::ToString;

    use tc_asn1::{Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x509::AlgorithmIdentifier;

    use super::EncryptedPrivateKeyInfo;

    #[test]
    fn encrypted_private_keys_preserve_algorithm_parameters_and_ciphertext() {
        let algorithm = AlgorithmIdentifier::with_null("1.2.3".parse().unwrap());
        let info =
            EncryptedPrivateKeyInfo::new(algorithm.clone(), Asn1OctetString::new(&[0xab, 0xcd]));
        let wire = [0x30, 12, 0x30, 6, 6, 2, 0x2a, 3, 5, 0, 4, 2, 0xab, 0xcd];
        assert_eq!(info.encryption_algorithm(), &algorithm);
        assert_eq!(info.encrypted_data().as_bytes(), &[0xab, 0xcd]);
        assert_eq!(info.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            EncryptedPrivateKeyInfo::decode_der(&wire, &DecodingOptions::default()).unwrap(),
            (wire.len(), info.clone())
        );
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::CER,
            EncodingOptions::DER,
        ] {
            let wire = info.encode_to_vec(&rules).unwrap();
            assert_eq!(wire.len(), info.encoded_len(&rules));
            assert_eq!(
                EncryptedPrivateKeyInfo::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                info
            );
        }
        assert_eq!(info.to_string(), "1.2.3 NULL, 2 ciphertext octets");
    }

    #[test]
    fn encrypted_key_containers_do_not_impose_ciphertext_length_or_algorithm_policy() {
        for bytes in [&[][..], &[0xff; 2048][..]] {
            let info = EncryptedPrivateKeyInfo::new(
                AlgorithmIdentifier::new("1.2.3.4".parse().unwrap()),
                Asn1OctetString::new(bytes),
            );
            let wire = info.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                EncryptedPrivateKeyInfo::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                info
            );
        }
    }

    #[test]
    fn encrypted_key_sequences_require_an_algorithm_then_octets_and_no_extra_field() {
        for (wire, error) in [
            (&[0x30, 0][..], Asn1Error::Truncated),
            (&[0x30, 6, 0x30, 4, 6, 2, 0x2a, 3][..], Asn1Error::Truncated),
            (&[0x31, 0][..], Asn1Error::UnexpectedTag),
            (&[0x30, 2, 4, 0][..], Asn1Error::UnexpectedTag),
            (
                &[0x30, 8, 0x30, 4, 6, 2, 0x2a, 3, 5, 0][..],
                Asn1Error::UnexpectedTag,
            ),
            (
                &[0x30, 10, 0x30, 4, 6, 2, 0x2a, 3, 4, 0, 5, 0][..],
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                EncryptedPrivateKeyInfo::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
