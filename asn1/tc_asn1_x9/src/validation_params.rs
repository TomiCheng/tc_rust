//! X9.42 Diffie-Hellman domain validation parameters.
//!
//! ```text
//! ValidationParams ::= SEQUENCE {
//!     seed        BIT STRING,
//!     pgenCounter INTEGER }
//! ```
//!
//! The values are carried as encoded; regenerating the domain parameters
//! from the seed belongs to the validator.

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The seed and counter that generated a set of X9.42 domain parameters.
///
/// ```
/// use tc_asn1::{Asn1BitString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::ValidationParams;
///
/// let params = ValidationParams::new(Asn1BitString::from_bytes(&[0x5a; 20]), 42.into());
/// let der = params.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(ValidationParams::decode_der(&der, &DecodingOptions::default())?.1, params);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ValidationParams {
    seed: Asn1BitString,
    pgen_counter: Asn1Integer,
}

impl ValidationParams {
    /// Stores the seed and counter without checking them against any domain.
    /// Variable time: branches only on the encoding structure.
    pub fn new(seed: Asn1BitString, pgen_counter: Asn1Integer) -> Self {
        Self { seed, pgen_counter }
    }

    /// Returns the generation seed.
    /// Variable time: branches only on the encoding structure.
    pub fn seed(&self) -> &Asn1BitString {
        &self.seed
    }

    /// Returns the generation counter.
    /// Variable time: branches only on the encoding structure.
    pub fn pgen_counter(&self) -> &Asn1Integer {
        &self.pgen_counter
    }
}

impl DecodeInner for ValidationParams {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let seed = fields.get()?;
        let pgen_counter = fields.get()?;
        fields.end()?;
        Ok((element.total_len(), Self::new(seed, pgen_counter)))
    }
}

impl EncodeContent for ValidationParams {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.seed.encoded_len(rules) + self.pgen_counter.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.seed.encode(rules, out)?;
        at += self.pgen_counter.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for ValidationParams {}

impl Tagged for ValidationParams {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ValidationParams {}

impl Encode for ValidationParams {
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

    use super::ValidationParams;

    #[test]
    fn the_seed_and_counter_encode_in_order_and_round_trip_under_every_rule() {
        let value = ValidationParams::new(Asn1BitString::from_bytes(&[0xab, 0xcd]), 300.into());
        assert_eq!(
            value.encode_to_vec(&EncodingOptions::DER).unwrap(),
            [
                0x30, 0x09, 0x03, 0x03, 0x00, 0xab, 0xcd, 0x02, 0x02, 0x01, 0x2c
            ]
        );
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::DER,
            EncodingOptions::CER,
        ] {
            let wire = value.encode_to_vec(&rules).unwrap();
            assert_eq!(
                ValidationParams::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn missing_swapped_or_extra_fields_are_rejected() {
        for (wire, error) in [
            (&b"\x30\x04\x03\x02\x00\xab"[..], Asn1Error::Truncated),
            (
                &b"\x30\x07\x02\x01\x01\x03\x02\x00\xab"[..],
                Asn1Error::UnexpectedTag,
            ),
            (
                &b"\x30\x0a\x03\x02\x00\xab\x02\x01\x01\x02\x01\x01"[..],
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                ValidationParams::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
