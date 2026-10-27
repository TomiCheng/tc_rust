//! RFC 5652 §6.2.2 `KeyAgreeRecipientInfo`, recipients whose key-encryption key
//! comes from a key agreement, such as ECDH.
//!
//! ```text
//! KeyAgreeRecipientInfo ::= SEQUENCE {
//!     version CMSVersion,  -- always set to 3
//!     originator [0] EXPLICIT OriginatorIdentifierOrKey,
//!     ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
//!     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//!     recipientEncryptedKeys RecipientEncryptedKeys }
//! UserKeyingMaterial ::= OCTET STRING
//! RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Asn1SequenceOf, Children, Decode,
    DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::recipient::{OriginatorIdentifierOrKey, RecipientEncryptedKey};

/// Key-agreement recipients that share one originator key.
///
/// The version is always 3; a decoded version that differs is kept.
///
/// ```
/// use tc_asn1::{Asn1BitString, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::recipient::{KeyAgreeRecipientInfo, OriginatorPublicKey, RecipientEncryptedKey};
/// use tc_asn1_cms::signed::IssuerAndSerialNumber;
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// // Ephemeral-static ECDH: the sender's ephemeral key, then one wrapped key per recipient.
/// let ephemeral = OriginatorPublicKey::new(
///     AlgorithmIdentifier::new("1.2.840.10045.2.1".parse()?),
///     Asn1BitString::from_bytes(&[0x04; 65]),
/// );
/// let recipient = RecipientEncryptedKey::new(
///     IssuerAndSerialNumber::new("CN=Recipient".parse()?, 2.into()).into(),
///     Asn1OctetString::new(&[0x55; 24]),
/// );
/// let kari = KeyAgreeRecipientInfo::new(
///     ephemeral.into(),
///     AlgorithmIdentifier::new("1.3.132.1.11.1".parse()?), // dhSinglePass-stdDH-sha256kdf-scheme
///     vec![recipient],
/// );
/// assert_eq!(kari.version(), 3.into());
/// let der = kari.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(KeyAgreeRecipientInfo::decode_der(&der, &DecodingOptions::default())?.1, kari);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct KeyAgreeRecipientInfo {
    version: Option<Asn1Integer>,
    originator: OriginatorIdentifierOrKey,
    ukm: Option<Asn1OctetString>,
    key_encryption_algorithm: AlgorithmIdentifier,
    recipient_encrypted_keys: Asn1SequenceOf<RecipientEncryptedKey>,
}

impl KeyAgreeRecipientInfo {
    /// The originator, the key-encryption algorithm and the recipients, without user
    /// keying material.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        originator: OriginatorIdentifierOrKey,
        key_encryption_algorithm: AlgorithmIdentifier,
        recipient_encrypted_keys: Vec<RecipientEncryptedKey>,
    ) -> Self {
        Self {
            version: None,
            originator,
            ukm: None,
            key_encryption_algorithm,
            recipient_encrypted_keys: Asn1SequenceOf::new(recipient_encrypted_keys),
        }
    }

    /// Adds the user keying material that makes the key-encryption key unique.
    /// Variable time: branches only on the encoding structure.
    pub fn with_ukm(mut self, ukm: Asn1OctetString) -> Self {
        self.ukm = Some(ukm);
        self
    }

    /// Returns the decoded version, or the one RFC 5652 §6.2.2 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// Always 3.
    fn derived_version(&self) -> Asn1Integer {
        3.into()
    }

    /// Returns the originator.
    /// Variable time: branches only on the encoding structure.
    pub fn originator(&self) -> &OriginatorIdentifierOrKey {
        &self.originator
    }

    /// Returns the user keying material, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn ukm(&self) -> Option<&Asn1OctetString> {
        self.ukm.as_ref()
    }

    /// Returns the key-agreement and key-wrap algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn key_encryption_algorithm(&self) -> &AlgorithmIdentifier {
        &self.key_encryption_algorithm
    }

    /// Returns the recipients and their wrapped keys.
    /// Variable time: branches only on the encoding structure.
    pub fn recipient_encrypted_keys(&self) -> &[RecipientEncryptedKey] {
        self.recipient_encrypted_keys.elements()
    }
}

impl DecodeContent for KeyAgreeRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let originator = fields.get_explicit::<OriginatorIdentifierOrKey>([0xa0])?;
        let ukm = fields.get_explicit_opt::<Asn1OctetString>([0xa1])?;
        let key_encryption_algorithm = fields.get()?;
        let recipient_encrypted_keys = fields.get()?;
        fields.end()?;
        let mut value = Self {
            version: None,
            originator,
            ukm,
            key_encryption_algorithm,
            recipient_encrypted_keys,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for KeyAgreeRecipientInfo {
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

impl EncodeContent for KeyAgreeRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + Explicit::new(&[0xa0], &self.originator).encoded_len(rules)
            + self
                .ukm
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self.key_encryption_algorithm.encoded_len(rules)
            + self.recipient_encrypted_keys.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += Explicit::new(&[0xa0], &self.originator).encode(rules, &mut out[at..])?;
        if let Some(v) = &self.ukm {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        at += self
            .key_encryption_algorithm
            .encode(rules, &mut out[at..])?;
        at += self
            .recipient_encrypted_keys
            .encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for KeyAgreeRecipientInfo {}

impl Tagged for KeyAgreeRecipientInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for KeyAgreeRecipientInfo {}

impl Encode for KeyAgreeRecipientInfo {
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
    use alloc::vec;

    use tc_asn1::{Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::KeyAgreeRecipientInfo;
    use crate::fixtures::key_agree;

    #[test]
    fn the_originator_and_ukm_are_explicitly_tagged_and_round_trip() {
        let value = key_agree().with_ukm(Asn1OctetString::new(&[1; 64]));
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        // 30 81 LL: the long-form length puts the version at offset 3.
        assert_eq!(wire[3..6], [0x02, 0x01, 0x03]);
        assert_eq!(wire[6], 0xa0);
        for rules in [EncodingOptions::BER, EncodingOptions::DER] {
            let wire = value.encode_to_vec(&rules).unwrap();
            assert_eq!(
                KeyAgreeRecipientInfo::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn a_missing_originator_is_rejected() {
        let value = key_agree();
        let der = |v: &dyn Encode| v.encode_to_vec(&EncodingOptions::DER).unwrap();
        let body = [
            der(&value.version()),
            der(value.key_encryption_algorithm()),
            der(&tc_asn1::Asn1SequenceOf::new(
                value.recipient_encrypted_keys().to_vec(),
            )),
        ]
        .concat();
        let wire = [vec![0x30, body.len() as u8], body].concat();
        assert_eq!(
            KeyAgreeRecipientInfo::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
