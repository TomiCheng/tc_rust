//! X9.62 curve coefficients and optional generation seed.
//!
//! ```text
//! Curve ::= SEQUENCE { a FieldElement, b FieldElement, seed BIT STRING OPTIONAL }
//! FieldElement ::= OCTET STRING
//! ```
//!
//! Coefficient lengths are checked by `X9EcParameters`, which knows the field.

use core::fmt;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// Curve coefficients, without field arithmetic.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::Curve;
///
/// let curve = Curve::new(Asn1OctetString::new(&[1]), Asn1OctetString::new(&[2]));
/// let der = curve.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(Curve::decode_der(&der, &DecodingOptions::default())?.1, curve);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Curve {
    a: Asn1OctetString,
    b: Asn1OctetString,
    seed: Option<Asn1BitString>,
}

impl Curve {
    /// Stores the coefficients without applying a field-dependent length rule.
    /// Variable time: branches only on the encoding structure.
    pub fn new(a: Asn1OctetString, b: Asn1OctetString) -> Self {
        Self { a, b, seed: None }
    }

    /// Adds the generation seed.
    /// Variable time: branches only on the encoding structure.
    pub fn with_seed(mut self, seed: Asn1BitString) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Returns coefficient a.
    /// Variable time: branches only on the encoding structure.
    pub fn a(&self) -> &Asn1OctetString {
        &self.a
    }

    /// Returns coefficient b.
    /// Variable time: branches only on the encoding structure.
    pub fn b(&self) -> &Asn1OctetString {
        &self.b
    }

    /// Returns the generation seed, if supplied.
    /// Variable time: branches only on the encoding structure.
    pub fn seed(&self) -> Option<&Asn1BitString> {
        self.seed.as_ref()
    }
}

impl fmt::Display for Curve {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a: {} octets, b: {} octets",
            self.a.as_bytes().len(),
            self.b.as_bytes().len()
        )
    }
}

impl DecodeInner for Curve {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let a = fields.get()?;
        let b = fields.get()?;
        let seed = fields.get_opt()?;
        fields.end()?;
        let mut value = Self::new(a, b);
        value.seed = seed;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for Curve {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.a.encoded_len(rules)
            + self.b.encoded_len(rules)
            + self.seed.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.a.encode(rules, out)?;
        at += self.b.encode(rules, &mut out[at..])?;
        if let Some(value) = &self.seed {
            at += value.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for Curve {}

impl Tagged for Curve {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Curve {}

impl Encode for Curve {
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
        Asn1BitString, Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    use super::Curve;

    #[test]
    fn coefficients_round_trip_with_and_without_a_seed() {
        let curve = Curve::new(Asn1OctetString::new(&[1]), Asn1OctetString::new(&[2]));
        for (value, wire) in [
            (curve.clone(), &b"\x30\x06\x04\x01\x01\x04\x01\x02"[..]),
            (
                curve.with_seed(Asn1BitString::from_bytes(&[0xaa])),
                &b"\x30\x0a\x04\x01\x01\x04\x01\x02\x03\x02\x00\xaa"[..],
            ),
        ] {
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                Curve::decode_der(wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn coefficient_tags_missing_coefficients_and_extra_fields_are_checked() {
        for (wire, error) in [
            (&b"\x30\x02\x05\x00"[..], Asn1Error::UnexpectedTag),
            (&b"\x30\x02\x04\x00"[..], Asn1Error::Truncated),
            (
                &b"\x30\x06\x04\x00\x04\x00\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                Curve::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
