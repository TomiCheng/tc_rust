//! RFC 5652 §6.2.2 `RecipientEncryptedKey`, one key-agreement recipient and the
//! content-encryption key wrapped for it.
//!
//! ```text
//! RecipientEncryptedKey ::= SEQUENCE {
//!     rid KeyAgreeRecipientIdentifier,
//!     encryptedKey EncryptedKey }
//! ```

use crate::recipient::KeyAgreeRecipientIdentifier;
use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A recipient of a key agreement and its wrapped key.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RecipientEncryptedKey {
    rid: KeyAgreeRecipientIdentifier,
    encrypted_key: Asn1OctetString,
}

impl RecipientEncryptedKey {
    /// Stores the recipient identifier and the wrapped key.
    /// Variable time: branches only on the encoding structure.
    pub fn new(rid: KeyAgreeRecipientIdentifier, encrypted_key: Asn1OctetString) -> Self {
        Self { rid, encrypted_key }
    }

    /// Returns the recipient identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn rid(&self) -> &KeyAgreeRecipientIdentifier {
        &self.rid
    }

    /// Returns the wrapped content-encryption key.
    /// Variable time: branches only on the encoding structure.
    pub fn encrypted_key(&self) -> &Asn1OctetString {
        &self.encrypted_key
    }
}

impl DecodeContent for RecipientEncryptedKey {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let rid = fields.get()?;
        let encrypted_key = fields.get()?;
        fields.end()?;
        let value = Self { rid, encrypted_key };
        Ok(value)
    }
}

impl DecodeInner for RecipientEncryptedKey {
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

impl EncodeContent for RecipientEncryptedKey {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.rid.encoded_len(rules) + self.encrypted_key.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.rid.encode(rules, out)?;
        at += self.encrypted_key.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for RecipientEncryptedKey {}

impl Tagged for RecipientEncryptedKey {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RecipientEncryptedKey {}

impl Encode for RecipientEncryptedKey {
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
    use tc_asn1::{Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::RecipientEncryptedKey;
    use crate::signed::IssuerAndSerialNumber;

    #[test]
    fn the_identifier_and_wrapped_key_round_trip() {
        let value = RecipientEncryptedKey::new(
            IssuerAndSerialNumber::new("CN=R".parse().unwrap(), 3.into()).into(),
            Asn1OctetString::new(&[8; 24]),
        );
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            RecipientEncryptedKey::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
        assert_eq!(
            RecipientEncryptedKey::decode_der(
                &[0x30, 0x02, 0x04, 0x00],
                &DecodingOptions::default()
            ),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
