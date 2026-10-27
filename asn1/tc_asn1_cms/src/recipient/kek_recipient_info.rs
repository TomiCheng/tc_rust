//! RFC 5652 §6.2.3 `KEKRecipientInfo`, a recipient that holds a previously
//! distributed symmetric key-encryption key.
//!
//! ```text
//! KEKRecipientInfo ::= SEQUENCE {
//!     version CMSVersion,  -- always set to 4
//!     kekid KEKIdentifier,
//!     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//!     encryptedKey EncryptedKey }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::recipient::KekIdentifier;

/// A recipient of a shared key-encryption key.
///
/// The version is always 4; a decoded version that differs is kept.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct KekRecipientInfo {
    version: Option<Asn1Integer>,
    kekid: KekIdentifier,
    key_encryption_algorithm: AlgorithmIdentifier,
    encrypted_key: Asn1OctetString,
}

impl KekRecipientInfo {
    /// The key identifier, the key-wrap algorithm and the wrapped key.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        kekid: KekIdentifier,
        key_encryption_algorithm: AlgorithmIdentifier,
        encrypted_key: Asn1OctetString,
    ) -> Self {
        Self {
            version: None,
            kekid,
            key_encryption_algorithm,
            encrypted_key,
        }
    }

    /// Returns the decoded version, or the one RFC 5652 §6.2.3 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// Always 4.
    fn derived_version(&self) -> Asn1Integer {
        4.into()
    }

    /// Returns the key-encryption key identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn kekid(&self) -> &KekIdentifier {
        &self.kekid
    }

    /// Returns the key-wrap algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn key_encryption_algorithm(&self) -> &AlgorithmIdentifier {
        &self.key_encryption_algorithm
    }

    /// Returns the wrapped content-encryption key.
    /// Variable time: branches only on the encoding structure.
    pub fn encrypted_key(&self) -> &Asn1OctetString {
        &self.encrypted_key
    }
}

impl DecodeContent for KekRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let kekid = fields.get()?;
        let key_encryption_algorithm = fields.get()?;
        let encrypted_key = fields.get()?;
        fields.end()?;
        let mut value = Self {
            version: None,
            kekid,
            key_encryption_algorithm,
            encrypted_key,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for KekRecipientInfo {
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

impl EncodeContent for KekRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.kekid.encoded_len(rules)
            + self.key_encryption_algorithm.encoded_len(rules)
            + self.encrypted_key.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.kekid.encode(rules, &mut out[at..])?;
        at += self
            .key_encryption_algorithm
            .encode(rules, &mut out[at..])?;
        at += self.encrypted_key.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for KekRecipientInfo {}

impl Tagged for KekRecipientInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for KekRecipientInfo {}

impl Encode for KekRecipientInfo {
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
    use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};

    use super::KekRecipientInfo;
    use crate::fixtures::kek;

    #[test]
    fn the_version_is_four_and_the_recipient_round_trips() {
        let value = kek();
        assert_eq!(value.version(), 4.into());
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire[2..5], [0x02, 0x01, 0x04]);
        assert_eq!(
            KekRecipientInfo::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }
}
