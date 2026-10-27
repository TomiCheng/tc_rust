//! RFC 5652 §6.2.4 `PasswordRecipientInfo`, a recipient whose key-encryption key
//! is derived from a password.
//!
//! ```text
//! PasswordRecipientInfo ::= SEQUENCE {
//!     version CMSVersion,   -- always set to 0
//!     keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,   -- IMPLICIT
//!     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//!     encryptedKey EncryptedKey }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// A password recipient.
///
/// The version is always 0; a decoded version that differs is kept.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PasswordRecipientInfo {
    version: Option<Asn1Integer>,
    key_derivation_algorithm: Option<AlgorithmIdentifier>,
    key_encryption_algorithm: AlgorithmIdentifier,
    encrypted_key: Asn1OctetString,
}

impl PasswordRecipientInfo {
    /// The key-wrap algorithm and the wrapped key, without a key-derivation
    /// algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        key_encryption_algorithm: AlgorithmIdentifier,
        encrypted_key: Asn1OctetString,
    ) -> Self {
        Self {
            version: None,
            key_derivation_algorithm: None,
            key_encryption_algorithm,
            encrypted_key,
        }
    }

    /// Adds the key-derivation algorithm, such as PBKDF2 with its parameters.
    /// Variable time: branches only on the encoding structure.
    pub fn with_key_derivation_algorithm(
        mut self,
        key_derivation_algorithm: AlgorithmIdentifier,
    ) -> Self {
        self.key_derivation_algorithm = Some(key_derivation_algorithm);
        self
    }

    /// Returns the decoded version, or the one RFC 5652 §6.2.4 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// Always 0.
    fn derived_version(&self) -> Asn1Integer {
        0.into()
    }

    /// Returns the key-derivation algorithm, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn key_derivation_algorithm(&self) -> Option<&AlgorithmIdentifier> {
        self.key_derivation_algorithm.as_ref()
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

impl DecodeContent for PasswordRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let key_derivation_algorithm = fields.get_implicit_opt([0xa0])?;
        let key_encryption_algorithm = fields.get()?;
        let encrypted_key = fields.get()?;
        fields.end()?;
        let mut value = Self {
            version: None,
            key_derivation_algorithm,
            key_encryption_algorithm,
            encrypted_key,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for PasswordRecipientInfo {
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

impl EncodeContent for PasswordRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self
                .key_derivation_algorithm
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
            + self.key_encryption_algorithm.encoded_len(rules)
            + self.encrypted_key.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        if let Some(v) = &self.key_derivation_algorithm {
            at += Implicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += self
            .key_encryption_algorithm
            .encode(rules, &mut out[at..])?;
        at += self.encrypted_key.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for PasswordRecipientInfo {}

impl Tagged for PasswordRecipientInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PasswordRecipientInfo {}

impl Encode for PasswordRecipientInfo {
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

    use super::PasswordRecipientInfo;
    use crate::fixtures::{alg, password};

    #[test]
    fn the_key_derivation_algorithm_goes_under_an_implicit_zero() {
        let value = password().with_key_derivation_algorithm(alg("1.2.840.113549.1.5.12"));
        assert_eq!(value.version(), 0.into());
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire[5..9], [0xa0, 0x0b, 0x06, 0x09]);
        for value in [password(), value] {
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                PasswordRecipientInfo::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }
}
