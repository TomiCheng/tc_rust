//! X9.42 Diffie-Hellman domain parameters, the `dhpublicnumber` key parameters.
//!
//! ```text
//! DomainParameters ::= SEQUENCE {
//!     p                INTEGER,           -- odd prime, p = jq + 1
//!     g                INTEGER,           -- generator, g
//!     q                INTEGER,           -- factor of p-1
//!     j                INTEGER OPTIONAL,  -- subgroup factor, j >= 2
//!     validationParams ValidationParams OPTIONAL }
//! ```
//!
//! No arithmetic relation between the values is checked; validating the group
//! belongs to the key-agreement layer.

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::ValidationParams;

/// X9.42 Diffie-Hellman group parameters, without group arithmetic.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::DomainParameters;
///
/// let params = DomainParameters::new(23.into(), 4.into(), 11.into()).with_j(2.into());
/// let der = params.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(DomainParameters::decode_der(&der, &DecodingOptions::default())?.1, params);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DomainParameters {
    p: Asn1Integer,
    g: Asn1Integer,
    q: Asn1Integer,
    j: Option<Asn1Integer>,
    validation_params: Option<ValidationParams>,
}

impl DomainParameters {
    /// Stores the prime, generator and subgroup order without checking them.
    /// Variable time: branches only on the encoding structure.
    pub fn new(p: Asn1Integer, g: Asn1Integer, q: Asn1Integer) -> Self {
        Self {
            p,
            g,
            q,
            j: None,
            validation_params: None,
        }
    }

    /// Adds the subgroup factor.
    /// Variable time: branches only on the encoding structure.
    pub fn with_j(mut self, j: Asn1Integer) -> Self {
        self.j = Some(j);
        self
    }

    /// Adds the generation seed and counter.
    /// Variable time: branches only on the encoding structure.
    pub fn with_validation_params(mut self, validation_params: ValidationParams) -> Self {
        self.validation_params = Some(validation_params);
        self
    }

    /// Returns the prime modulus.
    /// Variable time: branches only on the encoding structure.
    pub fn p(&self) -> &Asn1Integer {
        &self.p
    }

    /// Returns the generator.
    /// Variable time: branches only on the encoding structure.
    pub fn g(&self) -> &Asn1Integer {
        &self.g
    }

    /// Returns the subgroup order.
    /// Variable time: branches only on the encoding structure.
    pub fn q(&self) -> &Asn1Integer {
        &self.q
    }

    /// Returns the subgroup factor, if supplied.
    /// Variable time: branches only on the encoding structure.
    pub fn j(&self) -> Option<&Asn1Integer> {
        self.j.as_ref()
    }

    /// Returns the generation seed and counter, if supplied.
    /// Variable time: branches only on the encoding structure.
    pub fn validation_params(&self) -> Option<&ValidationParams> {
        self.validation_params.as_ref()
    }
}

impl DecodeInner for DomainParameters {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let p = fields.get()?;
        let g = fields.get()?;
        let q = fields.get()?;
        let j = fields.get_opt()?;
        let validation_params = fields.get_opt()?;
        fields.end()?;
        let mut value = Self::new(p, g, q);
        value.j = j;
        value.validation_params = validation_params;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for DomainParameters {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.p.encoded_len(rules)
            + self.g.encoded_len(rules)
            + self.q.encoded_len(rules)
            + self.j.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self
                .validation_params
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.p.encode(rules, out)?;
        at += self.g.encode(rules, &mut out[at..])?;
        at += self.q.encode(rules, &mut out[at..])?;
        if let Some(value) = &self.j {
            at += value.encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.validation_params {
            at += value.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for DomainParameters {}

impl Tagged for DomainParameters {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for DomainParameters {}

impl Encode for DomainParameters {
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

    use super::DomainParameters;
    use crate::ValidationParams;

    fn base() -> DomainParameters {
        DomainParameters::new(23.into(), 4.into(), 11.into())
    }

    #[test]
    fn the_three_required_integers_encode_alone_when_nothing_optional_is_set() {
        assert_eq!(
            base().encode_to_vec(&EncodingOptions::DER).unwrap(),
            [
                0x30, 0x09, 0x02, 0x01, 0x17, 0x02, 0x01, 0x04, 0x02, 0x01, 0x0b
            ]
        );
    }

    #[test]
    fn every_combination_of_optional_fields_round_trips_under_every_rule() {
        let validation = ValidationParams::new(Asn1BitString::from_bytes(&[1, 2, 3]), 7.into());
        for j in [false, true] {
            for validated in [false, true] {
                let mut value = base();
                if j {
                    value = value.with_j(2.into());
                }
                if validated {
                    value = value.with_validation_params(validation.clone());
                }
                for rules in [
                    EncodingOptions::BER,
                    EncodingOptions::DER,
                    EncodingOptions::CER,
                ] {
                    let wire = value.encode_to_vec(&rules).unwrap();
                    let decoded = DomainParameters::decode(&wire, &DecodingOptions::default())
                        .unwrap()
                        .1;
                    assert_eq!(decoded, value);
                    assert_eq!(decoded.j().is_some(), j);
                    assert_eq!(decoded.validation_params().is_some(), validated);
                }
            }
        }
    }

    #[test]
    fn missing_integers_misplaced_optionals_and_trailing_data_are_rejected() {
        for (wire, error) in [
            (&b"\x30\x06\x02\x01\x17\x02\x01\x04"[..], Asn1Error::Truncated),
            // validationParams before j.
            (
                &b"\x30\x15\x02\x01\x17\x02\x01\x04\x02\x01\x0b\x30\x07\x03\x02\x00\x01\x02\x01\x01\x02\x01\x02"[..],
                Asn1Error::TrailingData,
            ),
            (
                &b"\x30\x0b\x02\x01\x17\x02\x01\x04\x02\x01\x0b\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                DomainParameters::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
