//! RFC 8017 A.1.1 RSA public keys.
//!
//! ```text
//! RSAPublicKey ::= SEQUENCE {
//!     modulus        INTEGER,
//!     publicExponent INTEGER }
//! ```
//!
//! Both integers must be positive. Key size and exponent policy belong to the caller.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged, tag,
};

/// An RSA modulus and public exponent, with no arithmetic validation.
///
/// ```
/// use tc_asn1_pkcs::RsaPublicKey;
///
/// let key = RsaPublicKey::new(323.into(), 5.into())?;
/// assert_eq!(key.modulus(), &323.into());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RsaPublicKey {
    modulus: Asn1Integer,
    public_exponent: Asn1Integer,
}

impl RsaPublicKey {
    /// Rejects a zero or negative modulus or exponent with `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(modulus: Asn1Integer, public_exponent: Asn1Integer) -> Result<Self, Asn1Error> {
        if [&modulus, &public_exponent]
            .iter()
            .any(|v| v.is_negative() || v.as_bytes() == [0])
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            modulus,
            public_exponent,
        })
    }

    /// Returns the modulus.
    /// Variable time: branches only on the encoding structure.
    pub fn modulus(&self) -> &Asn1Integer {
        &self.modulus
    }

    /// Returns the public exponent.
    /// Variable time: branches only on the encoding structure.
    pub fn public_exponent(&self) -> &Asn1Integer {
        &self.public_exponent
    }
}

impl fmt::Display for RsaPublicKey {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "n: {}, e: {}", self.modulus, self.public_exponent)
    }
}

impl DecodeInner for RsaPublicKey {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let modulus = fields.get()?;
        let exponent = fields.get()?;
        fields.end()?;
        Ok((element.total_len(), Self::new(modulus, exponent)?))
    }
}

impl EncodeContent for RsaPublicKey {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.modulus.encoded_len(rules) + self.public_exponent.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        at += self.modulus.encode(rules, &mut out[at..])?;
        at += self.public_exponent.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for RsaPublicKey {}

impl Tagged for RsaPublicKey {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RsaPublicKey {}

impl Encode for RsaPublicKey {
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

    use tc_asn1::{Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::RsaPublicKey;

    #[test]
    fn the_public_key_vector_round_trips_and_displays_both_integers() {
        let key = RsaPublicKey::new(323.into(), 5.into()).unwrap();
        let wire = b"\x30\x07\x02\x02\x01\x43\x02\x01\x05";
        assert_eq!(key.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            RsaPublicKey::decode(wire, &DecodingOptions::default()).unwrap(),
            (wire.len(), key.clone())
        );
        assert_eq!(
            RsaPublicKey::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            key
        );
        assert_eq!(key.to_string(), "n: 323, e: 5");
        assert_eq!(key.public_exponent(), &5.into());
    }

    #[test]
    fn both_public_key_integers_must_be_positive_on_construction_and_decoding() {
        for (n, e) in [(0, 1), (-1, 1), (1, 0), (1, -1)] {
            assert_eq!(
                RsaPublicKey::new(n.into(), e.into()),
                Err(Asn1Error::MalformedValue)
            );
            let wire = [0x30, 6, 2, 1, n as u8, 2, 1, e as u8];
            assert_eq!(
                RsaPublicKey::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn public_keys_require_exactly_two_integer_fields_inside_a_sequence() {
        for (wire, error) in [
            (&b"\x30\x03\x02\x01\x01"[..], Asn1Error::Truncated),
            (
                &b"\x30\x08\x02\x01\x01\x02\x01\x01\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
            (
                &b"\x31\x06\x02\x01\x01\x02\x01\x01"[..],
                Asn1Error::UnexpectedTag,
            ),
            (
                &b"\x30\x05\x05\x00\x02\x01\x01"[..],
                Asn1Error::UnexpectedTag,
            ),
        ] {
            assert_eq!(
                RsaPublicKey::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }

    #[test]
    fn public_key_storage_preserves_large_values_without_enforcing_exponent_policy() {
        let key =
            RsaPublicKey::new(Asn1Integer::from_unsigned_bytes(&[0xff; 300]), 2.into()).unwrap();
        let wire = key.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            RsaPublicKey::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            key
        );
        assert!(RsaPublicKey::new(1.into(), 2.into()).is_ok());
    }
}
