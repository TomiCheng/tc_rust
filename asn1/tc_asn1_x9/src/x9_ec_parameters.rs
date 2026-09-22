//! X9.62 explicit elliptic-curve domain parameters.
//!
//! ```text
//! ECParameters ::= SEQUENCE {
//!     version INTEGER { ecpVer1(1) } (ecpVer1),
//!     fieldID FieldID, curve Curve, base ECPoint, order INTEGER,
//!     cofactor INTEGER OPTIONAL }
//! ECPoint ::= OCTET STRING
//! ```
//!
//! Known fields determine coefficient and point widths. Unknown fields skip
//! width checks, but still require a supported point prefix. No curve arithmetic,
//! primality, point membership or subgroup validation is performed.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::{Curve, FieldId};

/// Explicit domain parameters with version one and structurally consistent widths.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::{Curve, FieldId, X9EcParameters};
///
/// let value = X9EcParameters::new(
///     FieldId::prime_field(251)?,
///     Curve::new(Asn1OctetString::new(&[1]), Asn1OctetString::new(&[2])),
///     Asn1OctetString::new(&[4, 3, 4]), 17.into(),
/// )?.with_cofactor(1.into())?;
/// let der = value.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(X9EcParameters::decode_der(&der, &DecodingOptions::default())?.1, value);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct X9EcParameters {
    field_id: FieldId,
    curve: Curve,
    base: Asn1OctetString,
    order: Asn1Integer,
    cofactor: Option<Asn1Integer>,
}

impl X9EcParameters {
    /// Checks field-element widths, point encoding shape and a positive order.
    /// Violations return `MalformedValue`; no arithmetic validation is performed.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        field_id: FieldId,
        curve: Curve,
        base: Asn1OctetString,
        order: Asn1Integer,
    ) -> Result<Self, Asn1Error> {
        field_id.validate()?;
        let width = field_id.field_size_bytes();
        if width.is_some_and(|n| curve.a().as_bytes().len() != n || curve.b().as_bytes().len() != n)
        {
            return Err(Asn1Error::MalformedValue);
        }
        let bytes = base.as_bytes();
        let expected = match bytes.first() {
            Some(0) => Some(1),
            Some(2 | 3) => width.and_then(|n| n.checked_add(1)),
            Some(4 | 6 | 7) => width.and_then(|n| n.checked_mul(2)?.checked_add(1)),
            _ => return Err(Asn1Error::MalformedValue),
        };
        if expected.is_some_and(|n| n != bytes.len()) || !positive(&order) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            field_id,
            curve,
            base,
            order,
            cofactor: None,
        })
    }

    /// Sets a positive cofactor; zero or negative values return `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn with_cofactor(mut self, cofactor: Asn1Integer) -> Result<Self, Asn1Error> {
        if !positive(&cofactor) {
            return Err(Asn1Error::MalformedValue);
        }
        self.cofactor = Some(cofactor);
        Ok(self)
    }

    /// Returns the field definition.
    /// Variable time: branches only on the encoding structure.
    pub fn field_id(&self) -> &FieldId {
        &self.field_id
    }

    /// Returns the coefficients and optional seed.
    /// Variable time: branches only on the encoding structure.
    pub fn curve(&self) -> &Curve {
        &self.curve
    }

    /// Returns the encoded base point.
    /// Variable time: branches only on the encoding structure.
    pub fn base(&self) -> &Asn1OctetString {
        &self.base
    }

    /// Returns the subgroup order.
    /// Variable time: branches only on the encoding structure.
    pub fn order(&self) -> &Asn1Integer {
        &self.order
    }

    /// Returns the optional cofactor.
    /// Variable time: branches only on the encoding structure.
    pub fn cofactor(&self) -> Option<&Asn1Integer> {
        self.cofactor.as_ref()
    }
}

fn positive(value: &Asn1Integer) -> bool {
    !value.is_negative() && value.as_bytes() != [0]
}

impl fmt::Display for X9EcParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, order {}", self.field_id, self.order)
    }
}

impl DecodeInner for X9EcParameters {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        if fields.get::<Asn1Integer>()?.as_bytes() != [1] {
            return Err(Asn1Error::MalformedValue);
        }
        let field_id = fields.get()?;
        let curve = fields.get()?;
        let base = fields.get()?;
        let order = fields.get()?;
        let cofactor = fields.get_opt()?;
        fields.end()?;
        let mut value = Self::new(field_id, curve, base, order)?;
        if let Some(cofactor) = cofactor {
            value = value.with_cofactor(cofactor)?;
        }
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for X9EcParameters {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        3 + self.field_id.encoded_len(rules)
            + self.curve.encoded_len(rules)
            + self.base.encoded_len(rules)
            + self.order.encoded_len(rules)
            + self.cofactor.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out.get_mut(..3)
            .ok_or(Asn1Error::BufferTooSmall)?
            .copy_from_slice(&[2, 1, 1]);
        let mut at = 3;
        at += self.field_id.encode(rules, &mut out[at..])?;
        at += self.curve.encode(rules, &mut out[at..])?;
        at += self.base.encode(rules, &mut out[at..])?;
        at += self.order.encode(rules, &mut out[at..])?;
        if let Some(value) = &self.cofactor {
            at += value.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for X9EcParameters {}

impl Tagged for X9EcParameters {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for X9EcParameters {}

impl Encode for X9EcParameters {
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
    use alloc::{vec, vec::Vec};

    use tc_asn1::{
        Asn1Error, Asn1Integer, Asn1Null, Asn1OctetString, Decode, DecodingOptions, Encode,
        EncodingOptions,
    };

    use super::X9EcParameters;
    use crate::{Curve, FieldId};

    fn curve(a: &[u8], b: &[u8]) -> Curve {
        Curve::new(Asn1OctetString::new(a), Asn1OctetString::new(b))
    }

    fn unchecked_wire(curve: &Curve, base: &[u8], order: i32) -> Vec<u8> {
        let rules = EncodingOptions::DER;
        let mut contents = vec![2, 1, 1];
        contents.extend(
            FieldId::prime_field(251)
                .unwrap()
                .encode_to_vec(&rules)
                .unwrap(),
        );
        contents.extend(curve.encode_to_vec(&rules).unwrap());
        contents.extend(Asn1OctetString::new(base).encode_to_vec(&rules).unwrap());
        contents.extend(Asn1Integer::from(order).encode_to_vec(&rules).unwrap());
        let mut wire = vec![0x30, contents.len() as u8];
        wire.extend(contents);
        wire
    }

    #[test]
    fn the_synthetic_prime_field_has_the_correct_sign_octet_and_sequence_lengths() {
        let value = X9EcParameters::new(
            FieldId::prime_field(251).unwrap(),
            curve(&[1], &[2]),
            Asn1OctetString::new(&[4, 3, 4]),
            17.into(),
        )
        .unwrap()
        .with_cofactor(1.into())
        .unwrap();
        let wire = [
            0x30, 0x25, 2, 1, 1, 0x30, 0x0d, 6, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 1, 1, 2, 2, 0,
            0xfb, 0x30, 6, 4, 1, 1, 4, 1, 2, 4, 3, 4, 3, 4, 2, 1, 17, 2, 1, 1,
        ];
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            X9EcParameters::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
        assert_eq!(
            X9EcParameters::decode(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn both_coefficients_must_match_the_known_field_width() {
        for (a, b) in [
            (&[][..], &[2][..]),
            (&[1, 2][..], &[2][..]),
            (&[1][..], &[][..]),
            (&[1][..], &[2, 3][..]),
        ] {
            let c = curve(a, b);
            assert_eq!(
                X9EcParameters::new(
                    FieldId::prime_field(251).unwrap(),
                    c.clone(),
                    Asn1OctetString::new(&[0]),
                    1.into()
                ),
                Err(Asn1Error::MalformedValue)
            );
            assert_eq!(
                X9EcParameters::decode_der(
                    &unchecked_wire(&c, &[0], 1),
                    &DecodingOptions::default()
                ),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn each_point_prefix_requires_its_exact_length_and_unknown_prefixes_are_rejected() {
        for (prefix, length) in [
            (0, 1),
            (2, 2),
            (3, 2),
            (4, 3),
            (6, 3),
            (7, 3),
            (5, usize::MAX),
        ] {
            for size in 0..6 {
                let mut bytes = vec![0; size];
                if size != 0 {
                    bytes[0] = prefix;
                }
                let value = X9EcParameters::new(
                    FieldId::prime_field(251).unwrap(),
                    curve(&[1], &[2]),
                    Asn1OctetString::new(&bytes),
                    1.into(),
                );
                let decoded = X9EcParameters::decode_der(
                    &unchecked_wire(&curve(&[1], &[2]), &bytes, 1),
                    &DecodingOptions::default(),
                );
                if size == length {
                    assert_eq!(decoded.unwrap().1, value.unwrap());
                } else {
                    assert_eq!(value, Err(Asn1Error::MalformedValue));
                    assert_eq!(decoded, Err(Asn1Error::MalformedValue));
                }
            }
        }
    }

    #[test]
    fn version_order_and_cofactor_constraints_apply_to_decoding_too() {
        for n in [0, -1] {
            assert_eq!(
                X9EcParameters::new(
                    FieldId::prime_field(251).unwrap(),
                    curve(&[1], &[2]),
                    Asn1OctetString::new(&[0]),
                    n.into()
                ),
                Err(Asn1Error::MalformedValue)
            );
            assert_eq!(
                X9EcParameters::decode_der(
                    &unchecked_wire(&curve(&[1], &[2]), &[0], n),
                    &DecodingOptions::default()
                ),
                Err(Asn1Error::MalformedValue)
            );
            let wire = unchecked_wire(&curve(&[1], &[2]), &[0], 1);
            let value = X9EcParameters::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1;
            assert_eq!(
                value.with_cofactor(n.into()),
                Err(Asn1Error::MalformedValue)
            );
            let mut bad = wire.clone();
            bad.extend_from_slice(&[2, 1, n as u8]);
            bad[1] += 3;
            assert_eq!(
                X9EcParameters::decode_der(&bad, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
            let mut bad_version = wire;
            bad_version[4] = n as u8;
            assert_eq!(
                X9EcParameters::decode_der(&bad_version, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn unknown_fields_skip_width_checks_but_still_check_point_prefixes() {
        for base in [&b"\x02"[..], &b"\x04\x01\x02\x03\x04"[..]] {
            let field = FieldId::other("1.2.3".parse().unwrap(), Asn1Null.into()).unwrap();
            let value = X9EcParameters::new(
                field,
                curve(&[], &[1, 2, 3]),
                Asn1OctetString::new(base),
                1.into(),
            )
            .unwrap();
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                X9EcParameters::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
        for base in [&b"\x05"[..], &b"\x00\x00"[..]] {
            let field = FieldId::other("1.2.3".parse().unwrap(), Asn1Null.into()).unwrap();
            assert_eq!(
                X9EcParameters::new(field, curve(&[], &[]), Asn1OctetString::new(base), 1.into()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }
}
