//! RFC 5753 §7.2 `MQVuserKeyingMaterial`, the user keying material of 1-Pass
//! ECMQV: the originator's ephemeral key and optional extra material.
//!
//! ```text
//! MQVuserKeyingMaterial ::= SEQUENCE {
//!     ephemeralPublicKey  OriginatorPublicKey,
//!     addedukm            [0] EXPLICIT UserKeyingMaterial OPTIONAL }
//! ```

use crate::recipient::OriginatorPublicKey;
use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

/// The ECMQV ephemeral key, carried as the `ukm` of a key-agreement recipient.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MqvUserKeyingMaterial {
    ephemeral_public_key: OriginatorPublicKey,
    added_ukm: Option<Asn1OctetString>,
}

impl MqvUserKeyingMaterial {
    /// The ephemeral public key, without added keying material.
    /// Variable time: branches only on the encoding structure.
    pub fn new(ephemeral_public_key: OriginatorPublicKey) -> Self {
        Self {
            ephemeral_public_key,
            added_ukm: None,
        }
    }

    /// Adds user keying material beyond the ephemeral key.
    /// Variable time: branches only on the encoding structure.
    pub fn with_added_ukm(mut self, added_ukm: Asn1OctetString) -> Self {
        self.added_ukm = Some(added_ukm);
        self
    }

    /// Returns the originator's ephemeral public key.
    /// Variable time: branches only on the encoding structure.
    pub fn ephemeral_public_key(&self) -> &OriginatorPublicKey {
        &self.ephemeral_public_key
    }

    /// Returns the added user keying material, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn added_ukm(&self) -> Option<&Asn1OctetString> {
        self.added_ukm.as_ref()
    }
}

impl DecodeContent for MqvUserKeyingMaterial {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let ephemeral_public_key = fields.get()?;
        let added_ukm = fields.get_explicit_opt::<Asn1OctetString>([0xa0])?;
        fields.end()?;
        let value = Self {
            ephemeral_public_key,
            added_ukm,
        };
        Ok(value)
    }
}

impl DecodeInner for MqvUserKeyingMaterial {
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

impl EncodeContent for MqvUserKeyingMaterial {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.ephemeral_public_key.encoded_len(rules)
            + self
                .added_ukm
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.ephemeral_public_key.encode(rules, out)?;
        if let Some(v) = &self.added_ukm {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for MqvUserKeyingMaterial {}

impl Tagged for MqvUserKeyingMaterial {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for MqvUserKeyingMaterial {}

impl Encode for MqvUserKeyingMaterial {
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
    use tc_asn1::{
        Asn1BitString, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    use super::MqvUserKeyingMaterial;
    use crate::fixtures::alg;
    use crate::recipient::OriginatorPublicKey;

    #[test]
    fn the_ephemeral_key_and_added_ukm_round_trip() {
        let key = OriginatorPublicKey::new(
            alg("1.2.840.10045.2.1"),
            Asn1BitString::from_bytes(&[4; 65]),
        );
        let bare = MqvUserKeyingMaterial::new(key);
        let added = bare.clone().with_added_ukm(Asn1OctetString::new(&[9; 8]));
        let wire = added.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            wire[wire.len() - 12..wire.len() - 8],
            [0xa0, 0x0a, 0x04, 0x08]
        );
        for value in [bare, added] {
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                MqvUserKeyingMaterial::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }
}
