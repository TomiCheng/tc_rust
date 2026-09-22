//! X9.62 characteristic-two fields and polynomial bases.
//!
//! ```text
//! Characteristic-two ::= SEQUENCE { m INTEGER, basis OBJECT IDENTIFIER,
//!                                   parameters ANY DEFINED BY basis }
//! Pentanomial ::= SEQUENCE { k1 INTEGER, k2 INTEGER, k3 INTEGER }
//! -- gnBasis: NULL; tpBasis: INTEGER; ppBasis: Pentanomial
//! ```
//!
//! Exponents are bounded by u32. These types check ordering, not irreducibility.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Null, Asn1Object, Asn1Oid, Asn1Ref, Decode, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, NamedOid, Tagged, tag,
};

use crate::encoding::{Exponent, OidRef};

/// Three increasing positive exponents.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::Pentanomial;
///
/// let value = Pentanomial::new(1, 2, 3)?;
/// let der = value.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(Pentanomial::decode_der(&der, &DecodingOptions::default())?.1, value);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Pentanomial {
    k1: u32,
    k2: u32,
    k3: u32,
}

impl Pentanomial {
    /// Requires `0 < k1 < k2 < k3`; the enclosing field checks `k3 < m`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(k1: u32, k2: u32, k3: u32) -> Result<Self, Asn1Error> {
        if k1 == 0 || k1 >= k2 || k2 >= k3 {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { k1, k2, k3 })
    }

    /// Returns the first exponent.
    /// Variable time: branches only on the encoding structure.
    pub fn k1(&self) -> u32 {
        self.k1
    }

    /// Returns the second exponent.
    /// Variable time: branches only on the encoding structure.
    pub fn k2(&self) -> u32 {
        self.k2
    }

    /// Returns the third exponent.
    /// Variable time: branches only on the encoding structure.
    pub fn k3(&self) -> u32 {
        self.k3
    }
}

impl fmt::Display for Pentanomial {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, {}, {}", self.k1, self.k2, self.k3)
    }
}

impl DecodeInner for Pentanomial {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let k1 = exponent(fields.get()?)?;
        let k2 = exponent(fields.get()?)?;
        let k3 = exponent(fields.get()?)?;
        fields.end()?;
        Ok((element.total_len(), Self::new(k1, k2, k3)?))
    }
}

impl EncodeContent for Pentanomial {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        [self.k1, self.k2, self.k3]
            .iter()
            .map(|v| Exponent(*v).encoded_len(rules))
            .sum()
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        for value in [self.k1, self.k2, self.k3] {
            at += Exponent(value).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for Pentanomial {}

impl Tagged for Pentanomial {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Pentanomial {}

impl Encode for Pentanomial {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

/// An unknown basis OID and its parameter tree. Construct through [`Basis::other`].
///
/// ```
/// use tc_asn1::{Asn1Null, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::{Basis, CharacteristicTwo};
///
/// let value = CharacteristicTwo::new(5, Basis::other("1.2.3".parse()?, Asn1Null.into())?)?;
/// let der = value.encode_to_vec(&EncodingOptions::DER)?;
/// let back = CharacteristicTwo::decode_der(&der, &DecodingOptions::default())?.1;
/// if let Basis::Other(unknown) = back.basis() { assert_eq!(unknown.basis().to_string(), "1.2.3"); }
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UnknownBasis {
    basis: Asn1Oid,
    parameters: Asn1Object,
}

impl UnknownBasis {
    /// Returns the unrecognized basis identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn basis(&self) -> &Asn1Oid {
        &self.basis
    }

    /// Returns its parameter tree.
    /// Variable time: branches only on the encoding structure.
    pub fn parameters(&self) -> &Asn1Object {
        &self.parameters
    }
}

/// A basis OID bound to its parameter type; encoded as part of a field.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::{Basis, CharacteristicTwo};
///
/// let value = CharacteristicTwo::new(5, Basis::Trinomial(2))?;
/// let der = value.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(CharacteristicTwo::decode_der(&der, &DecodingOptions::default())?.1, value);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Basis {
    /// Gaussian normal basis with a NULL parameter.
    Gaussian,
    /// Trinomial basis with its middle exponent.
    Trinomial(u32),
    /// Pentanomial basis with three middle exponents.
    Pentanomial(Pentanomial),
    /// Unrecognized basis with its parameter tree.
    Other(UnknownBasis),
}

impl Basis {
    /// Gaussian normal basis.
    pub const GN_BASIS: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 1, 2, 3, 1],
        "1.2.840.10045.1.2.3.1",
        "gnBasis",
    );
    /// Trinomial basis.
    pub const TP_BASIS: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 1, 2, 3, 2],
        "1.2.840.10045.1.2.3.2",
        "tpBasis",
    );
    /// Pentanomial basis.
    pub const PP_BASIS: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 1, 2, 3, 3],
        "1.2.840.10045.1.2.3.3",
        "ppBasis",
    );

    /// Preserves an unknown basis; recognized identifiers return `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn other(basis: Asn1Oid, parameters: Asn1Object) -> Result<Self, Asn1Error> {
        if Self::GN_BASIS == basis || Self::TP_BASIS == basis || Self::PP_BASIS == basis {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self::Other(UnknownBasis { basis, parameters }))
    }

    /// Returns the identifier selected by the variant.
    /// Variable time: branches only on the encoding structure.
    pub fn basis(&self) -> Asn1Oid {
        match self {
            Self::Gaussian => Self::GN_BASIS.into(),
            Self::Trinomial(_) => Self::TP_BASIS.into(),
            Self::Pentanomial(_) => Self::PP_BASIS.into(),
            Self::Other(v) => v.basis.clone(),
        }
    }

    fn oid_ref(&self) -> OidRef<'_> {
        OidRef(match self {
            Self::Gaussian => Self::GN_BASIS.as_der(),
            Self::Trinomial(_) => Self::TP_BASIS.as_der(),
            Self::Pentanomial(_) => Self::PP_BASIS.as_der(),
            Self::Other(v) => v.basis.as_bytes(),
        })
    }

    fn parameter_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Gaussian => Asn1Null.encoded_len(rules),
            Self::Trinomial(k) => Exponent(*k).encoded_len(rules),
            Self::Pentanomial(v) => v.encoded_len(rules),
            Self::Other(v) => v.parameters.encoded_len(rules),
        }
    }

    fn encode_parameter(
        &self,
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        match self {
            Self::Gaussian => Asn1Null.encode(rules, out),
            Self::Trinomial(k) => Exponent(*k).encode(rules, out),
            Self::Pentanomial(v) => v.encode(rules, out),
            Self::Other(v) => v.parameters.encode(rules, out),
        }
    }
}

impl fmt::Display for Basis {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gaussian => f.write_str("gnBasis"),
            Self::Trinomial(k) => write!(f, "tpBasis: {k}"),
            Self::Pentanomial(v) => write!(f, "ppBasis: {v}"),
            Self::Other(v) => v.basis.fmt(f),
        }
    }
}

/// A binary field size and its basis, without arithmetic validation.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::{Basis, CharacteristicTwo};
///
/// let field = CharacteristicTwo::new(163, Basis::Trinomial(7))?;
/// let der = field.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(CharacteristicTwo::decode_der(&der, &DecodingOptions::default())?.1, field);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CharacteristicTwo {
    m: u32,
    basis: Basis,
}

impl CharacteristicTwo {
    /// Requires a positive field size and polynomial exponents strictly below it.
    /// Variable time: branches only on the encoding structure.
    pub fn new(m: u32, basis: Basis) -> Result<Self, Asn1Error> {
        if m == 0
            || match &basis {
                Basis::Trinomial(k) => *k == 0 || *k >= m,
                Basis::Pentanomial(v) => v.k3 >= m,
                _ => false,
            }
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { m, basis })
    }

    /// Returns the field degree.
    /// Variable time: branches only on the encoding structure.
    pub fn m(&self) -> u32 {
        self.m
    }

    /// Returns the basis.
    /// Variable time: branches only on the encoding structure.
    pub fn basis(&self) -> &Basis {
        &self.basis
    }
}

impl fmt::Display for CharacteristicTwo {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "2^{}, {}", self.m, self.basis)
    }
}

fn exponent(value: Asn1Integer) -> Result<u32, Asn1Error> {
    u32::try_from(&value).map_err(|_| Asn1Error::MalformedValue)
}

impl DecodeInner for CharacteristicTwo {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let m = exponent(fields.get()?)?;
        let oid = fields.get::<Asn1Oid>()?;
        let basis = if Basis::GN_BASIS == oid {
            fields.get::<Asn1Null>()?;
            Basis::Gaussian
        } else if Basis::TP_BASIS == oid {
            Basis::Trinomial(exponent(fields.get()?)?)
        } else if Basis::PP_BASIS == oid {
            Basis::Pentanomial(fields.get()?)
        } else {
            Basis::other(oid, fields.get()?)?
        };
        fields.end()?;
        Ok((element.total_len(), Self::new(m, basis)?))
    }
}

impl EncodeContent for CharacteristicTwo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        Exponent(self.m).encoded_len(rules)
            + self.basis.oid_ref().encoded_len(rules)
            + self.basis.parameter_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = Exponent(self.m).encode(rules, out)?;
        at += self.basis.oid_ref().encode(rules, &mut out[at..])?;
        at += self.basis.encode_parameter(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for CharacteristicTwo {}

impl Tagged for CharacteristicTwo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CharacteristicTwo {}

impl Encode for CharacteristicTwo {
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

    use super::{Basis, CharacteristicTwo, Pentanomial};

    #[test]
    fn each_known_basis_has_the_expected_parameter_tag_and_round_trips() {
        for (basis, wire) in [
            (
                Basis::Gaussian,
                &[
                    0x30, 16, 2, 1, 5, 6, 9, 0x2a, 0x86, 0x48, 0xce, 0x3d, 1, 2, 3, 1, 5, 0,
                ][..],
            ),
            (
                Basis::Trinomial(2),
                &[
                    0x30, 17, 2, 1, 5, 6, 9, 0x2a, 0x86, 0x48, 0xce, 0x3d, 1, 2, 3, 2, 2, 1, 2,
                ][..],
            ),
            (
                Basis::Pentanomial(Pentanomial::new(1, 2, 3).unwrap()),
                &[
                    0x30, 25, 2, 1, 5, 6, 9, 0x2a, 0x86, 0x48, 0xce, 0x3d, 1, 2, 3, 3, 0x30, 9, 2,
                    1, 1, 2, 1, 2, 2, 1, 3,
                ][..],
            ),
        ] {
            let value = CharacteristicTwo::new(5, basis).unwrap();
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                CharacteristicTwo::decode_der(wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn field_degrees_and_polynomial_exponents_must_be_positive_and_ordered() {
        assert_eq!(
            CharacteristicTwo::new(0, Basis::Gaussian),
            Err(Asn1Error::MalformedValue)
        );
        for k in [0, 5] {
            assert_eq!(
                CharacteristicTwo::new(5, Basis::Trinomial(k)),
                Err(Asn1Error::MalformedValue)
            );
            let mut wire =
                b"\x30\x11\x02\x01\x05\x06\x09\x2a\x86\x48\xce\x3d\x01\x02\x03\x02\x02\x01\x02"
                    .to_vec();
            wire[18] = k as u8;
            assert_eq!(
                CharacteristicTwo::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
        for (a, b, c) in [(0, 2, 3), (2, 1, 3), (1, 2, 2)] {
            assert_eq!(Pentanomial::new(a, b, c), Err(Asn1Error::MalformedValue));
            let wire = [0x30, 9, 2, 1, a as u8, 2, 1, b as u8, 2, 1, c as u8];
            assert_eq!(
                Pentanomial::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
        assert_eq!(
            CharacteristicTwo::new(3, Basis::Pentanomial(Pentanomial::new(1, 2, 3).unwrap())),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn decoded_pentanomial_exponents_must_be_below_m_and_fit_u32() {
        let equal = [
            0x30, 25, 2, 1, 3, 6, 9, 0x2a, 0x86, 0x48, 0xce, 0x3d, 1, 2, 3, 3, 0x30, 9, 2, 1, 1, 2,
            1, 2, 2, 1, 3,
        ];
        assert_eq!(
            CharacteristicTwo::decode_der(&equal, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
        let huge = [0x30, 13, 2, 1, 1, 2, 1, 2, 2, 5, 1, 0, 0, 0, 0];
        assert_eq!(
            Pentanomial::decode_der(&huge, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
        let negative = [0x30, 9, 2, 1, 0xff, 2, 1, 2, 2, 1, 3];
        assert_eq!(
            Pentanomial::decode_der(&negative, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn binary_fields_require_parameters_and_reject_a_fourth_field() {
        for (wire, error) in [
            (
                &b"\x30\x07\x02\x01\x05\x06\x02\x2a\x03"[..],
                Asn1Error::Truncated,
            ),
            (
                &b"\x30\x0b\x02\x01\x05\x06\x02\x2a\x03\x05\x00\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                CharacteristicTwo::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }

    #[test]
    fn gaussian_parameters_are_null_and_oversized_or_zero_degrees_are_rejected() {
        let wire = b"\x30\x10\x02\x01\x00\x06\x09\x2a\x86\x48\xce\x3d\x01\x02\x03\x01\x05\x00";
        assert_eq!(
            CharacteristicTwo::decode_der(wire, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
        let mut wrong = wire.to_vec();
        wrong[4] = 5;
        wrong[16] = 4;
        assert_eq!(
            CharacteristicTwo::decode_der(&wrong, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
        let huge = b"\x30\x14\x02\x05\x01\x00\x00\x00\x00\x06\x09\x2a\x86\x48\xce\x3d\x01\x02\x03\x01\x05\x00";
        assert_eq!(
            CharacteristicTwo::decode_der(huge, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn unknown_bases_preserve_the_parameter_tree_but_known_oids_cannot_use_other() {
        for oid in [Basis::GN_BASIS, Basis::TP_BASIS, Basis::PP_BASIS] {
            assert_eq!(
                Basis::other(oid.into(), Asn1Null.into()),
                Err(Asn1Error::MalformedValue)
            );
        }
        let value = CharacteristicTwo::new(
            5,
            Basis::other("1.2.3".parse().unwrap(), Asn1Null.into()).unwrap(),
        )
        .unwrap();
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            CharacteristicTwo::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }
}
