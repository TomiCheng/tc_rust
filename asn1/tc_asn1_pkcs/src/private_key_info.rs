//! RFC 5958 §2 private-key containers, including RFC 5208 PKCS#8.
//!
//! ```text
//! OneAsymmetricKey ::= SEQUENCE {
//!     version             INTEGER { v1(0), v2(1) },
//!     privateKeyAlgorithm AlgorithmIdentifier,
//!     privateKey          OCTET STRING,
//!     attributes      [0] IMPLICIT SET OF Attribute OPTIONAL,
//!     ...,
//!     [[2: publicKey  [1] IMPLICIT BIT STRING OPTIONAL ]],
//!     ... }
//! PrivateKeyInfo ::= OneAsymmetricKey
//! ```
//!
//! RFC 5208's PrivateKeyInfo is the version-zero case. This type also supports
//! RFC 5958's public key field; its presence determines version one.
//! Both context fields are IMPLICIT, unlike the EXPLICIT PSS and OAEP parameters.
//! Private-key octets are opaque, including any algorithm-specific inner encoding.
//! This container omits empty attribute lists and rejects a present empty set.

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Asn1SetOf, Decode,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit,
    Tagged, tag,
};
use tc_asn1_x500::Attribute;
use tc_asn1_x509::AlgorithmIdentifier;

/// An opaque private key, its algorithm and optional attributes and public key.
///
/// Secret octets are not wiped; the caller owns their lifetime, including input
/// and encoded output buffers. Debug redaction is a convenience, not a security
/// boundary. Equality and hashing are not constant time. The private key is not
/// parsed or checked against the algorithm or public key.
///
/// ```
/// use tc_asn1::Asn1OctetString;
/// use tc_asn1_pkcs::PrivateKeyInfo;
/// use tc_asn1_x509::AlgorithmIdentifier;
///
/// let info = PrivateKeyInfo::new(
///     AlgorithmIdentifier::new("1.3.101.112".parse()?),
///     Asn1OctetString::new(&[4, 2, 0x11, 0x22]),
/// );
/// assert_eq!(info.version(), 0);
/// assert_eq!(info.into_private_key().as_bytes(), &[4, 2, 0x11, 0x22]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct PrivateKeyInfo {
    algorithm: AlgorithmIdentifier,
    private_key: Asn1OctetString,
    attributes: Asn1SetOf<Attribute>,
    public_key: Option<Asn1BitString>,
}

impl PrivateKeyInfo {
    /// Stores the algorithm and opaque octets without imposing key policy.
    /// Variable time: branches only on the encoding structure.
    pub fn new(algorithm: AlgorithmIdentifier, private_key: Asn1OctetString) -> Self {
        Self {
            algorithm,
            private_key,
            attributes: Asn1SetOf::new(Vec::new()),
            public_key: None,
        }
    }

    /// Replaces the attributes. An empty list omits the field.
    /// Attribute validity is enforced by `Attribute`; no additional policy is imposed.
    /// Variable time: branches only on the encoding structure.
    pub fn with_attributes(mut self, attributes: Vec<Attribute>) -> Result<Self, Asn1Error> {
        self.attributes = Asn1SetOf::new(attributes);
        Ok(self)
    }

    /// Attaches public key bits and derives version one without checking the key pair.
    /// Variable time: branches only on the encoding structure.
    pub fn with_public_key(mut self, public_key: Asn1BitString) -> Self {
        self.public_key = Some(public_key);
        self
    }

    /// Returns one when the public key is present, or zero otherwise.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> u8 {
        u8::from(self.public_key.is_some())
    }

    /// Returns the private-key algorithm identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    /// Borrows the private key octets; the caller must protect them.
    /// Variable time: branches only on the encoding structure.
    pub fn private_key(&self) -> &Asn1OctetString {
        &self.private_key
    }

    /// Moves out the private key octets without cloning or wiping them.
    /// Variable time: branches only on the encoding structure.
    pub fn into_private_key(self) -> Asn1OctetString {
        self.private_key
    }

    /// Returns the attributes in construction or wire order; empty means absent.
    /// Variable time: branches only on the encoding structure.
    pub fn attributes(&self) -> &[Attribute] {
        self.attributes.members()
    }

    /// Returns the optional public key bits.
    /// Variable time: branches only on the encoding structure.
    pub fn public_key(&self) -> Option<&Asn1BitString> {
        self.public_key.as_ref()
    }
}

impl fmt::Debug for PrivateKeyInfo {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrivateKeyInfo {{ algorithm: {}, private_key: <redacted, {} octets>, .. }}",
            self.algorithm.algorithm(),
            self.private_key.as_bytes().len()
        )
    }
}

impl DecodeInner for PrivateKeyInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let version: Asn1Integer = fields.get()?;
        let algorithm = fields.get()?;
        let private_key = fields.get()?;
        let attributes = fields.get_implicit_opt::<Asn1SetOf<Attribute>>([0xa0])?;
        let public_key = fields.get_implicit_opt::<Asn1BitString>([0x81])?;
        fields.end()?;
        let mut value = Self::new(algorithm, private_key);
        if let Some(attributes) = attributes {
            if attributes.members().is_empty() {
                return Err(Asn1Error::MalformedValue);
            }
            value = value.with_attributes(attributes.into_members())?;
        }
        if let Some(public_key) = public_key {
            value = value.with_public_key(public_key);
        }
        if version.as_bytes() != [value.version()] {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for PrivateKeyInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        3 + self.algorithm.encoded_len(rules)
            + self.private_key.encoded_len(rules)
            + if self.attributes.members().is_empty() {
                0
            } else {
                Implicit::new(&[0xa0], &self.attributes).encoded_len(rules)
            }
            + self
                .public_key
                .as_ref()
                .map_or(0, |key| Implicit::new(&[0x81], key).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out.get_mut(..3)
            .ok_or(Asn1Error::BufferTooSmall)?
            .copy_from_slice(&[2, 1, self.version()]);
        let mut at = 3;
        at += self.algorithm.encode(rules, &mut out[at..])?;
        at += self.private_key.encode(rules, &mut out[at..])?;
        if !self.attributes.members().is_empty() {
            at += Implicit::new(&[0xa0], &self.attributes).encode(rules, &mut out[at..])?;
        }
        if let Some(key) = &self.public_key {
            at += Implicit::new(&[0x81], key).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for PrivateKeyInfo {}

impl Tagged for PrivateKeyInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PrivateKeyInfo {}

impl Encode for PrivateKeyInfo {
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
    use alloc::{format, vec, vec::Vec};

    use tc_asn1::{
        Asn1BitString, Asn1Error, Asn1OctetString, Asn1Oid, Decode, DecodingOptions, Encode,
        EncodeContent, EncodingOptions,
    };
    use tc_asn1_x500::{Attribute, DirectoryString};
    use tc_asn1_x509::AlgorithmIdentifier;

    use super::PrivateKeyInfo;

    fn sample() -> PrivateKeyInfo {
        let mut octets = vec![4, 32];
        octets.extend_from_slice(&[0x11; 32]);
        PrivateKeyInfo::new(
            AlgorithmIdentifier::new("1.3.101.112".parse().unwrap()),
            Asn1OctetString::new(&octets),
        )
    }

    fn vector() -> Vec<u8> {
        let mut wire = vec![
            0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
        ];
        wire.extend_from_slice(&[0x11; 32]);
        wire
    }

    fn attribute() -> Attribute {
        Attribute::new(
            "1.2.3".parse::<Asn1Oid>().unwrap(),
            vec![DirectoryString::new("A").unwrap().into()],
        )
        .unwrap()
    }

    fn append(mut wire: Vec<u8>, field: &[u8]) -> Vec<u8> {
        wire[1] += field.len() as u8;
        wire.extend_from_slice(field);
        wire
    }

    #[test]
    fn the_ed25519_container_preserves_the_inner_octet_string_and_moves_it_out() {
        let info = sample();
        let wire = vector();
        assert_eq!(info.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            PrivateKeyInfo::decode(&wire, &DecodingOptions::default()).unwrap(),
            (wire.len(), info.clone())
        );
        assert_eq!(
            PrivateKeyInfo::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            info
        );
        assert_eq!(info.version(), 0);
        assert_eq!(
            info.algorithm().algorithm(),
            &"1.3.101.112".parse::<Asn1Oid>().unwrap()
        );
        assert!(info.attributes().is_empty());
        assert!(info.public_key().is_none());
        let pointer = info.private_key().as_bytes().as_ptr();
        let octets = info.into_private_key();
        assert_eq!(octets.as_bytes().as_ptr(), pointer);
        assert_eq!(&octets.as_bytes()[..2], &[4, 32]);
        assert_eq!(&octets.as_bytes()[2..], &[0x11; 32]);
    }

    #[test]
    fn attributes_and_public_keys_use_implicit_tags_and_derive_the_version() {
        let bits = Asn1BitString::from_bytes(&[0xab]);
        let expected_attribute = [0xa0, 11, 0x30, 9, 6, 2, 0x2a, 3, 0x31, 3, 0x13, 1, b'A'];
        for has_attributes in [false, true] {
            for has_public in [false, true] {
                let mut info = sample();
                let mut expected = vector();
                if has_attributes {
                    info = info.with_attributes(vec![attribute()]).unwrap();
                    expected = append(expected, &expected_attribute);
                    assert_eq!(info.attributes(), &[attribute()]);
                }
                if has_public {
                    info = info.with_public_key(bits.clone());
                    expected[4] = 1;
                    expected = append(expected, &[0x81, 2, 0, 0xab]);
                    assert_eq!(info.public_key(), Some(&bits));
                }
                assert_eq!(info.version(), u8::from(has_public));
                assert_eq!(info.encode_to_vec(&EncodingOptions::DER).unwrap(), expected);
                assert_eq!(
                    PrivateKeyInfo::decode_der(&expected, &DecodingOptions::default())
                        .unwrap()
                        .1,
                    info
                );
                for rules in [
                    EncodingOptions::BER,
                    EncodingOptions::CER,
                    EncodingOptions::DER,
                ] {
                    let wire = info.encode_to_vec(&rules).unwrap();
                    assert_eq!(wire.len(), info.encoded_len(&rules));
                    assert_eq!(
                        PrivateKeyInfo::decode(&wire, &DecodingOptions::default())
                            .unwrap()
                            .1,
                        info
                    );
                    let mut content = vec![0; info.content_len(&rules)];
                    assert_eq!(
                        info.encode_content(&rules, &mut content).unwrap(),
                        content.len()
                    );
                }
            }
        }
    }

    #[test]
    fn empty_attribute_builders_omit_the_field_but_empty_wire_sets_are_rejected() {
        let cleared = sample()
            .with_attributes(vec![attribute()])
            .unwrap()
            .with_attributes(Vec::new())
            .unwrap();
        assert!(cleared.attributes().is_empty());
        assert_eq!(
            cleared.encode_to_vec(&EncodingOptions::DER).unwrap(),
            vector()
        );
        let wire = append(vector(), &[0xa0, 0]);
        assert_eq!(
            PrivateKeyInfo::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn private_key_versions_must_match_public_key_presence_and_be_zero_or_one() {
        for version in [1, 2, 255] {
            let mut wire = vector();
            wire[4] = version;
            assert_eq!(
                PrivateKeyInfo::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
        let wire = append(vector(), &[0x81, 2, 0, 0xab]);
        assert_eq!(
            PrivateKeyInfo::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn private_key_fields_reject_missing_extra_explicit_and_out_of_order_encodings() {
        let attribute_field = [0xa0, 11, 0x30, 9, 6, 2, 0x2a, 3, 0x31, 3, 0x13, 1, b'A'];
        let mut wrong_tag = vector();
        wrong_tag[0] = 0x31;
        let mut reversed = append(append(vector(), &[0x81, 2, 0, 0xab]), &attribute_field);
        reversed[4] = 1;
        for (wire, error) in [
            (vec![0x30, 3, 2, 1, 0], Asn1Error::Truncated),
            (
                vec![0x30, 10, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70],
                Asn1Error::Truncated,
            ),
            (wrong_tag, Asn1Error::UnexpectedTag),
            (append(vector(), &[5, 0]), Asn1Error::TrailingData),
            (
                append(vector(), &[0xa0, 2, 0x31, 0]),
                Asn1Error::UnexpectedTag,
            ),
            (
                append(vector(), &[0xa1, 4, 3, 2, 0, 0xab]),
                Asn1Error::TrailingData,
            ),
            (reversed, Asn1Error::TrailingData),
            (
                append(append(vector(), &attribute_field), &attribute_field),
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                PrivateKeyInfo::decode_der(&wire, &DecodingOptions::default()),
                Err(error)
            );
        }
        let mut duplicate_public =
            append(append(vector(), &[0x81, 2, 0, 0xab]), &[0x81, 2, 0, 0xab]);
        duplicate_public[4] = 1;
        assert_eq!(
            PrivateKeyInfo::decode_der(&duplicate_public, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
        assert_eq!(
            sample().encode_content(&EncodingOptions::DER, &mut [0; 2]),
            Err(Asn1Error::BufferTooSmall)
        );
    }

    #[test]
    fn private_key_debug_reports_the_algorithm_and_length_without_revealing_octets() {
        let info = PrivateKeyInfo::new(
            AlgorithmIdentifier::new("1.3.101.112".parse().unwrap()),
            Asn1OctetString::new(b"secret-private-key"),
        );
        let debug = format!("{info:?}");
        assert_eq!(
            debug,
            "PrivateKeyInfo { algorithm: 1.3.101.112, private_key: <redacted, 18 octets>, .. }"
        );
        assert!(!debug.contains("secret-private-key"));
    }

    #[test]
    fn opaque_private_octets_may_be_empty_or_not_asn1_and_ber_containers_normalize() {
        for octets in [&[][..], &[0xff, 0x80, 0][..], &[0x11; 2048][..]] {
            let info = PrivateKeyInfo::new(
                AlgorithmIdentifier::new("1.2.3.4".parse().unwrap()),
                Asn1OctetString::new(octets),
            );
            let wire = info.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                PrivateKeyInfo::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                info
            );
        }
        let mut indefinite = vector();
        indefinite[1] = 0x80;
        indefinite.extend_from_slice(&[0, 0]);
        let decoded = PrivateKeyInfo::decode(&indefinite, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(
            decoded.encode_to_vec(&EncodingOptions::DER).unwrap(),
            vector()
        );
        assert_eq!(
            PrivateKeyInfo::decode_der(&indefinite, &DecodingOptions::default()),
            Err(Asn1Error::NotDer)
        );
    }
}
