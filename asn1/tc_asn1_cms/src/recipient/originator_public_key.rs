//! RFC 5652 §6.2.2 `OriginatorPublicKey`, the sender's public key in a key
//! agreement, such as an ephemeral ECDH key.
//!
//! ```text
//! OriginatorPublicKey ::= SEQUENCE {
//!     algorithm AlgorithmIdentifier,
//!     publicKey BIT STRING }
//! ```

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The originator's public key and its algorithm, as in a SubjectPublicKeyInfo.
///
/// ```
/// use tc_asn1::{Asn1BitString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::recipient::OriginatorPublicKey;
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// let key = OriginatorPublicKey::new(
///     AlgorithmIdentifier::new("1.2.840.10045.2.1".parse()?),
///     Asn1BitString::from_bytes(&[0x04; 65]),
/// );
/// let der = key.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(OriginatorPublicKey::decode_der(&der, &DecodingOptions::default())?.1, key);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OriginatorPublicKey {
    algorithm: AlgorithmIdentifier,
    public_key: Asn1BitString,
}

impl OriginatorPublicKey {
    /// Stores the algorithm and the public key bits without checking them.
    /// Variable time: branches only on the encoding structure.
    pub fn new(algorithm: AlgorithmIdentifier, public_key: Asn1BitString) -> Self {
        Self {
            algorithm,
            public_key,
        }
    }

    /// Returns the public-key algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    /// Returns the public key bits.
    /// Variable time: branches only on the encoding structure.
    pub fn public_key(&self) -> &Asn1BitString {
        &self.public_key
    }
}

impl DecodeContent for OriginatorPublicKey {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let algorithm = fields.get()?;
        let public_key = fields.get()?;
        fields.end()?;
        let value = Self {
            algorithm,
            public_key,
        };
        Ok(value)
    }
}

impl DecodeInner for OriginatorPublicKey {
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

impl EncodeContent for OriginatorPublicKey {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.algorithm.encoded_len(rules) + self.public_key.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.algorithm.encode(rules, out)?;
        at += self.public_key.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for OriginatorPublicKey {}

impl Tagged for OriginatorPublicKey {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OriginatorPublicKey {}

impl Encode for OriginatorPublicKey {
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
    use tc_asn1::{Asn1BitString, Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::OriginatorPublicKey;
    use crate::fixtures::alg;

    #[test]
    fn the_algorithm_and_key_bits_encode_in_order() {
        let key = OriginatorPublicKey::new(alg("1.3.101.110"), Asn1BitString::from_bytes(&[9; 32]));
        let wire = key.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            wire[..9],
            [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e]
        );
        assert_eq!(wire[9..12], [0x03, 0x21, 0x00]);
        assert_eq!(
            OriginatorPublicKey::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            key
        );
        let only_algorithm = [
            &[0x30, 0x07][..],
            &alg("1.3.101.110")
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
        ]
        .concat();
        assert_eq!(
            OriginatorPublicKey::decode_der(&only_algorithm, &DecodingOptions::default()),
            Err(Asn1Error::Truncated)
        );
    }
}
