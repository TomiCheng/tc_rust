//! X9.62 named, explicit or inherited elliptic-curve parameters.
//!
//! ```text
//! Parameters ::= CHOICE {
//!     ecParameters ECParameters,
//!     namedCurve OBJECT IDENTIFIER,
//!     implicitlyCA NULL }
//! ```
//!
//! This represents the general X9.62 syntax, not a protocol-specific profile.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Null, Asn1Oid, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, tag,
};

use crate::{EcNamedCurve, X9EcParameters};

/// Curve parameters selected by their ASN.1 tag.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::{EcNamedCurve, X962Parameters};
///
/// let value = X962Parameters::from(EcNamedCurve::PRIME256V1.oid());
/// let der = value.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(X962Parameters::decode_der(&der, &DecodingOptions::default())?.1, value);
/// assert_eq!(value.to_string(), "prime256v1");
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
// Keep explicit parameters inline as part of the public value API, without an extra allocation.
#[allow(clippy::large_enum_variant)]
pub enum X962Parameters {
    /// Explicit domain parameters.
    EcParameters(X9EcParameters),
    /// A named curve, including identifiers outside the built-in table.
    NamedCurve(Asn1Oid),
    /// Parameters inherited from the issuing authority.
    ImplicitlyCa,
}

impl From<X9EcParameters> for X962Parameters {
    /// Variable time: branches only on the encoding structure.
    fn from(value: X9EcParameters) -> Self {
        Self::EcParameters(value)
    }
}

impl From<Asn1Oid> for X962Parameters {
    /// Variable time: branches only on the encoding structure.
    fn from(value: Asn1Oid) -> Self {
        Self::NamedCurve(value)
    }
}

impl X962Parameters {
    fn tag(&self) -> &'static [u8] {
        match self {
            Self::EcParameters(_) => tag::SEQUENCE,
            Self::NamedCurve(_) => tag::OBJECT_IDENTIFIER,
            Self::ImplicitlyCa => tag::NULL,
        }
    }
}

impl fmt::Display for X962Parameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EcParameters(_) => f.write_str("ecParameters"),
            Self::NamedCurve(oid) => match EcNamedCurve::from_oid(oid) {
                Some(value) => f.write_str(value.name()),
                None => oid.fmt(f),
            },
            Self::ImplicitlyCa => f.write_str("implicitlyCA"),
        }
    }
}

impl DecodeInner for X962Parameters {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        match element.tag() {
            [0x30] => {
                X9EcParameters::decode_inner(buff, context).map(|(n, v)| (n, Self::EcParameters(v)))
            }
            [0x06] => Asn1Oid::decode_inner(buff, context).map(|(n, v)| (n, Self::NamedCurve(v))),
            [0x05] => Asn1Null::decode_inner(buff, context).map(|(n, _)| (n, Self::ImplicitlyCa)),
            _ => Err(Asn1Error::UnexpectedTag),
        }
    }
}

impl Decode for X962Parameters {}

impl EncodeContent for X962Parameters {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::EcParameters(v) => v.content_len(rules),
            Self::NamedCurve(v) => v.content_len(rules),
            Self::ImplicitlyCa => Asn1Null.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::EcParameters(v) => v.encode_content(rules, out),
            Self::NamedCurve(v) => v.encode_content(rules, out),
            Self::ImplicitlyCa => Asn1Null.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for X962Parameters {}

impl Encode for X962Parameters {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(self.tag(), rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(self.tag(), rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::X962Parameters;

    #[test]
    fn all_parameter_choices_decode_by_tag_and_round_trip_without_extra_wrappers() {
        let explicit = [
            0x30, 0x25, 2, 1, 1, 0x30, 0x0d, 6, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 1, 1, 2, 2, 0,
            0xfb, 0x30, 6, 4, 1, 1, 4, 1, 2, 4, 3, 4, 3, 4, 2, 1, 17, 2, 1, 1,
        ];
        for (wire, text) in [
            (&explicit[..], "ecParameters"),
            (
                &b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"[..],
                "prime256v1",
            ),
            (&b"\x05\x00"[..], "implicitlyCA"),
            (&b"\x06\x02\x2a\x03"[..], "1.2.3"),
        ] {
            let value = X962Parameters::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1;
            assert_eq!(value.to_string(), text);
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                X962Parameters::decode(wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn unknown_choice_tags_and_nonempty_nulls_are_rejected() {
        assert_eq!(
            X962Parameters::decode_der(b"\x04\x00", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
        assert_eq!(
            X962Parameters::decode_der(b"\x05\x01\x00", &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }
}
