//! X9.42 Diffie-Hellman public keys, the `subjectPublicKey` of `dhpublicnumber`.
//!
//! ```text
//! DHPublicKey ::= INTEGER -- public key, y = g^x mod p
//! ```
//!
//! The range 1 < y < p - 1 and subgroup membership are checked by the
//! key-agreement layer, which knows the domain parameters.

use tc_asn1::{
    Asn1Error, Asn1Integer, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

/// An X9.42 Diffie-Hellman public value.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::dh::DhPublicKey;
///
/// let key = DhPublicKey::new(0x1234.into());
/// let der = key.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x02, 0x02, 0x12, 0x34]);
/// assert_eq!(DhPublicKey::decode_der(&der, &DecodingOptions::default())?.1, key);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DhPublicKey {
    y: Asn1Integer,
}

impl DhPublicKey {
    /// Stores the public value without a range check.
    /// Variable time: branches only on the encoding structure.
    pub fn new(y: Asn1Integer) -> Self {
        Self { y }
    }

    /// Returns the public value.
    /// Variable time: branches only on the encoding structure.
    pub fn y(&self) -> &Asn1Integer {
        &self.y
    }
}

impl From<Asn1Integer> for DhPublicKey {
    /// Variable time: branches only on the encoding structure.
    fn from(y: Asn1Integer) -> Self {
        Self::new(y)
    }
}

impl DecodeInner for DhPublicKey {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, y) = Asn1Integer::decode_inner(buff, context)?;
        Ok((len, Self::new(y)))
    }
}

impl DecodeContent for DhPublicKey {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        Asn1Integer::decode_content(value, context).map(Self::new)
    }
}

impl EncodeContent for DhPublicKey {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.y.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.y.encode_content(rules, out)
    }
}

impl Decode for DhPublicKey {}

impl Tagged for DhPublicKey {
    const TAG: &'static [u8] = <Asn1Integer as Tagged>::TAG;
}

impl EncodeTagged for DhPublicKey {}

impl Encode for DhPublicKey {
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
    use tc_asn1::{Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::DhPublicKey;

    #[test]
    fn the_public_value_is_a_bare_integer_with_a_sign_octet_when_needed() {
        let key = DhPublicKey::from(Asn1Integer::from_unsigned_bytes(&[0xff; 3]));
        let wire = key.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire, [0x02, 0x04, 0x00, 0xff, 0xff, 0xff]);
        assert_eq!(
            DhPublicKey::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            key
        );
    }

    #[test]
    fn anything_but_an_integer_is_rejected() {
        for wire in [&b"\x04\x01\x01"[..], &b"\x30\x03\x02\x01\x01"[..]] {
            assert_eq!(
                DhPublicKey::decode_der(wire, &DecodingOptions::default()),
                Err(Asn1Error::UnexpectedTag)
            );
        }
    }
}
