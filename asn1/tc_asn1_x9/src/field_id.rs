//! X9.62 field identifiers with OID-selected parameters.
//!
//! ```text
//! FieldID ::= SEQUENCE {
//!     fieldType OBJECT IDENTIFIER,
//!     parameters ANY DEFINED BY fieldType }
//! ```
//!
//! Prime fields require a positive odd modulus; primality is not checked.
//! Unknown parameters are preserved as an ASN.1 tree, not original BER octets.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Object, Asn1Oid, Asn1Ref, Decode, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, NamedOid, Tagged, tag,
};

use crate::CharacteristicTwo;
use crate::encoding::OidRef;

/// An unrecognized field identifier and its parameters. Use [`FieldId::other`].
///
/// ```
/// use tc_asn1::{Asn1Null, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::FieldId;
///
/// let field = FieldId::other("1.2.3".parse()?, Asn1Null.into())?;
/// let der = field.encode_to_vec(&EncodingOptions::DER)?;
/// let back = FieldId::decode_der(&der, &DecodingOptions::default())?.1;
/// if let FieldId::Other(value) = back { assert_eq!(value.field_type().to_string(), "1.2.3"); }
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UnknownField {
    field_type: Asn1Oid,
    parameters: Asn1Object,
}

impl UnknownField {
    /// Returns the unrecognized field OID.
    /// Variable time: branches only on the encoding structure.
    pub fn field_type(&self) -> &Asn1Oid {
        &self.field_type
    }

    /// Returns the parameter tree.
    /// Variable time: branches only on the encoding structure.
    pub fn parameters(&self) -> &Asn1Object {
        &self.parameters
    }
}

/// A field OID bound to its parameter type.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::FieldId;
///
/// let field = FieldId::prime_field(251)?;
/// assert_eq!(field.field_size_bytes(), Some(1));
/// let der = field.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(FieldId::decode_der(&der, &DecodingOptions::default())?.1, field);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum FieldId {
    /// A positive odd prime-field modulus; no primality test is performed.
    /// Prefer `prime_field`; encoding also validates directly constructed variants.
    PrimeField(Asn1Integer),
    /// A binary field and its basis.
    CharacteristicTwoField(CharacteristicTwo),
    /// Unknown field parameters.
    Other(UnknownField),
}

impl FieldId {
    /// Prime-field identifier.
    pub const PRIME_FIELD: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 1, 1],
        "1.2.840.10045.1.1",
        "prime-field",
    );
    /// Characteristic-two-field identifier.
    pub const CHARACTERISTIC_TWO_FIELD: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 1, 2],
        "1.2.840.10045.1.2",
        "characteristic-two-field",
    );

    /// Rejects an even or non-positive modulus with `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn prime_field(p: impl Into<Asn1Integer>) -> Result<Self, Asn1Error> {
        let value = Self::PrimeField(p.into());
        value.validate()?;
        Ok(value)
    }

    /// Wraps a validated binary-field description.
    /// Variable time: branches only on the encoding structure.
    pub fn characteristic_two_field(value: CharacteristicTwo) -> Self {
        Self::CharacteristicTwoField(value)
    }

    /// Preserves an unknown field; known OIDs return `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn other(field_type: Asn1Oid, parameters: Asn1Object) -> Result<Self, Asn1Error> {
        if Self::PRIME_FIELD == field_type || Self::CHARACTERISTIC_TWO_FIELD == field_type {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self::Other(UnknownField {
            field_type,
            parameters,
        }))
    }

    /// Returns the OID selected by the variant.
    /// Variable time: branches only on the encoding structure.
    pub fn field_type(&self) -> Asn1Oid {
        match self {
            Self::PrimeField(_) => Self::PRIME_FIELD.into(),
            Self::CharacteristicTwoField(_) => Self::CHARACTERISTIC_TWO_FIELD.into(),
            Self::Other(v) => v.field_type.clone(),
        }
    }

    fn oid_ref(&self) -> OidRef<'_> {
        OidRef(match self {
            Self::PrimeField(_) => Self::PRIME_FIELD.as_der(),
            Self::CharacteristicTwoField(_) => Self::CHARACTERISTIC_TWO_FIELD.as_der(),
            Self::Other(v) => v.field_type.as_bytes(),
        })
    }

    /// Returns the field element width, or `None` for unknown or invalid fields.
    /// Variable time: branches only on the encoding structure.
    pub fn field_size_bytes(&self) -> Option<usize> {
        match self {
            Self::PrimeField(p) => {
                self.validate().ok()?;
                Some(p.as_unsigned_bytes().ok()?.len())
            }
            Self::CharacteristicTwoField(v) => usize::try_from(v.m().div_ceil(8)).ok(),
            Self::Other(_) => None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Asn1Error> {
        if let Self::PrimeField(p) = self
            && (p.is_negative() || p.as_bytes().last().is_none_or(|b| b & 1 == 0))
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(())
    }
}

impl fmt::Display for FieldId {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrimeField(p) => write!(f, "prime-field: {p}"),
            Self::CharacteristicTwoField(v) => write!(f, "characteristic-two-field: {v}"),
            Self::Other(v) => v.field_type.fmt(f),
        }
    }
}

impl DecodeInner for FieldId {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let oid = fields.get::<Asn1Oid>()?;
        let value = if Self::PRIME_FIELD == oid {
            Self::prime_field(fields.get::<Asn1Integer>()?)?
        } else if Self::CHARACTERISTIC_TWO_FIELD == oid {
            Self::characteristic_two_field(fields.get()?)
        } else {
            Self::other(oid, fields.get()?)?
        };
        fields.end()?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for FieldId {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.oid_ref().encoded_len(rules)
            + match self {
                Self::PrimeField(v) => v.encoded_len(rules),
                Self::CharacteristicTwoField(v) => v.encoded_len(rules),
                Self::Other(v) => v.parameters.encoded_len(rules),
            }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.validate()?;
        let at = self.oid_ref().encode(rules, out)?;
        let n = match self {
            Self::PrimeField(v) => v.encode(rules, &mut out[at..])?,
            Self::CharacteristicTwoField(v) => v.encode(rules, &mut out[at..])?,
            Self::Other(v) => v.parameters.encode(rules, &mut out[at..])?,
        };
        Ok(at + n)
    }
}

impl Decode for FieldId {}

impl Tagged for FieldId {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for FieldId {}

impl Encode for FieldId {
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
    use tc_asn1::{Asn1Error, Asn1Null, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::FieldId;
    use crate::{Basis, CharacteristicTwo};

    #[test]
    fn a_251_modulus_has_a_sign_octet_but_one_octet_field_elements() {
        let value = FieldId::prime_field(251).unwrap();
        let wire = b"\x30\x0d\x06\x07\x2a\x86\x48\xce\x3d\x01\x01\x02\x02\x00\xfb";
        assert_eq!(value.field_size_bytes(), Some(1));
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            FieldId::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
        assert_eq!(
            FieldId::decode(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
        let binary = FieldId::characteristic_two_field(
            CharacteristicTwo::new(163, Basis::Trinomial(7)).unwrap(),
        );
        assert_eq!(binary.field_size_bytes(), Some(21));
        let der = binary.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            FieldId::decode_der(&der, &DecodingOptions::default())
                .unwrap()
                .1,
            binary
        );
    }

    #[test]
    fn even_and_nonpositive_moduli_are_rejected_even_for_direct_variants() {
        for p in [-1, 0, 2, 4] {
            assert_eq!(FieldId::prime_field(p), Err(Asn1Error::MalformedValue));
            let value = FieldId::PrimeField(p.into());
            assert_eq!(
                value.encode_to_vec(&EncodingOptions::DER),
                Err(Asn1Error::MalformedValue)
            );
            let mut wire = b"\x30\x0c\x06\x07\x2a\x86\x48\xce\x3d\x01\x01\x02\x01\x01".to_vec();
            wire[13] = p as u8;
            assert_eq!(
                FieldId::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn unknown_parameters_round_trip_as_der_and_known_oids_cannot_use_other() {
        let wire = b"\x30\x09\x06\x02\x2a\x03\x30\x03\x02\x01\x05";
        let value = FieldId::decode_der(wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(value.field_size_bytes(), None);
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        for oid in [FieldId::PRIME_FIELD, FieldId::CHARACTERISTIC_TWO_FIELD] {
            assert_eq!(
                FieldId::other(oid.into(), Asn1Null.into()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn field_parameters_are_required_and_no_third_field_is_allowed() {
        for (wire, error) in [
            (&b"\x30\x04\x06\x02\x2a\x03"[..], Asn1Error::Truncated),
            (
                &b"\x30\x08\x06\x02\x2a\x03\x05\x00\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
            (
                &b"\x30\x0b\x06\x07\x2a\x86\x48\xce\x3d\x01\x01\x05\x00"[..],
                Asn1Error::UnexpectedTag,
            ),
        ] {
            assert_eq!(
                FieldId::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
