//! RFC 5652 §6.2.1 `KeyTransRecipientInfo`, a recipient whose content-encryption
//! key is encrypted to its public key, as with RSA.
//!
//! ```text
//! KeyTransRecipientInfo ::= SEQUENCE {
//!     version CMSVersion,  -- always set to 0 or 2
//!     rid RecipientIdentifier,
//!     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//!     encryptedKey EncryptedKey }
//! EncryptedKey ::= OCTET STRING
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::recipient::RecipientIdentifier;

/// A key-transport recipient.
///
/// The version is 0 for an issuer and serial number and 2 for a key
/// identifier; a decoded version that differs is kept.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::recipient::KeyTransRecipientInfo;
/// use tc_asn1_cms::signed::IssuerAndSerialNumber;
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// let recipient = KeyTransRecipientInfo::new(
///     IssuerAndSerialNumber::new("CN=Recipient".parse()?, 2.into()).into(),
///     AlgorithmIdentifier::new("1.2.840.113549.1.1.7".parse()?), // RSAES-OAEP
///     Asn1OctetString::new(&[0x77; 256]),
/// );
/// assert_eq!(recipient.version(), 0.into());
/// let der = recipient.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(KeyTransRecipientInfo::decode_der(&der, &DecodingOptions::default())?.1, recipient);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct KeyTransRecipientInfo {
    version: Option<Asn1Integer>,
    rid: RecipientIdentifier,
    key_encryption_algorithm: AlgorithmIdentifier,
    encrypted_key: Asn1OctetString,
}

impl KeyTransRecipientInfo {
    /// A recipient, its key-encryption algorithm and the encrypted key.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        rid: RecipientIdentifier,
        key_encryption_algorithm: AlgorithmIdentifier,
        encrypted_key: Asn1OctetString,
    ) -> Self {
        Self {
            version: None,
            rid,
            key_encryption_algorithm,
            encrypted_key,
        }
    }

    /// Returns the decoded version, or the one RFC 5652 §6.2.1 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// 0 for an issuer and serial number, 2 for a key identifier.
    fn derived_version(&self) -> Asn1Integer {
        match self.rid {
            RecipientIdentifier::IssuerAndSerialNumber(_) => 0.into(),
            RecipientIdentifier::SubjectKeyIdentifier(_) => 2.into(),
        }
    }

    /// Returns the recipient identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn rid(&self) -> &RecipientIdentifier {
        &self.rid
    }

    /// Returns the key-encryption algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn key_encryption_algorithm(&self) -> &AlgorithmIdentifier {
        &self.key_encryption_algorithm
    }

    /// Returns the encrypted content-encryption key.
    /// Variable time: branches only on the encoding structure.
    pub fn encrypted_key(&self) -> &Asn1OctetString {
        &self.encrypted_key
    }
}

impl DecodeContent for KeyTransRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let rid = fields.get()?;
        let key_encryption_algorithm = fields.get()?;
        let encrypted_key = fields.get()?;
        fields.end()?;
        let mut value = Self {
            version: None,
            rid,
            key_encryption_algorithm,
            encrypted_key,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for KeyTransRecipientInfo {
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

impl EncodeContent for KeyTransRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.rid.encoded_len(rules)
            + self.key_encryption_algorithm.encoded_len(rules)
            + self.encrypted_key.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.rid.encode(rules, &mut out[at..])?;
        at += self
            .key_encryption_algorithm
            .encode(rules, &mut out[at..])?;
        at += self.encrypted_key.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for KeyTransRecipientInfo {}

impl Tagged for KeyTransRecipientInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for KeyTransRecipientInfo {}

impl Encode for KeyTransRecipientInfo {
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
    use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x509::ext::SubjectKeyIdentifier;

    use super::KeyTransRecipientInfo;
    use crate::fixtures::{alg, by_issuer_rid};

    fn recipient(rid: crate::recipient::RecipientIdentifier) -> KeyTransRecipientInfo {
        KeyTransRecipientInfo::new(
            rid,
            alg("1.2.840.113549.1.1.7"),
            Asn1OctetString::new(&[7; 16]),
        )
    }

    #[test]
    fn the_version_is_zero_by_issuer_and_two_by_key_identifier() {
        let by_issuer = recipient(by_issuer_rid());
        let by_key = recipient(
            SubjectKeyIdentifier::new(alloc::vec![1; 20])
                .unwrap()
                .into(),
        );
        assert_eq!(by_issuer.version(), 0.into());
        assert_eq!(by_key.version(), 2.into());
        for value in [by_issuer, by_key] {
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                KeyTransRecipientInfo::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn a_decoded_version_that_breaks_the_rule_is_kept() {
        let mut wire = recipient(by_issuer_rid())
            .encode_to_vec(&EncodingOptions::DER)
            .unwrap();
        assert_eq!(wire[2..5], [0x02, 0x01, 0x00]);
        wire[4] = 0x02;
        let back = KeyTransRecipientInfo::decode_der(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(back.version(), 2.into());
        assert_eq!(back.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
    }
}
