//! SEC 1 C.4 elliptic-curve private keys, using the RFC 5915 version-one shape.
//!
//! ```text
//! ECPrivateKey ::= SEQUENCE {
//!     version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//!     privateKey OCTET STRING,
//!     parameters [0] Parameters OPTIONAL, -- EXPLICIT
//!     publicKey [1] BIT STRING OPTIONAL } -- EXPLICIT
//! ```
//!
//! The general SEC 1 parameter choices are retained. RFC 5915's named-curve
//! and parameter-presence requirements belong to the consuming profile.

use core::fmt;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Decode, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

use crate::X962Parameters;

/// A private-key encoding container, not protected secret storage.
///
/// Octets are not wiped; the caller owns their lifetime, including input and
/// encoded output buffers. Debug redaction is a logging convenience, not a
/// security boundary. Equality and hashing are not constant-time operations.
/// Private key octets are copied without branching on their values; only their
/// public length affects construction and encoding control flow.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::{EcNamedCurve, EcPrivateKey};
///
/// let key = EcPrivateKey::new(Asn1OctetString::new(&[0x11; 32]))?
///     .with_parameters(EcNamedCurve::PRIME256V1.oid().into());
/// let der = key.encode_to_vec(&EncodingOptions::DER)?;
/// let decoded = EcPrivateKey::decode_der(&der, &DecodingOptions::default())?.1;
/// assert_eq!(decoded, key);
/// let octets = decoded.into_private_key();
/// assert_eq!(octets.as_bytes().len(), 32);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct EcPrivateKey {
    private_key: Asn1OctetString,
    parameters: Option<X962Parameters>,
    public_key: Option<Asn1BitString>,
}

impl EcPrivateKey {
    /// Requires non-empty private key octets; no scalar range check is performed.
    /// Variable time: branches only on the encoding structure.
    /// Private key octets are copied without branching on their values, only their public length.
    pub fn new(private_key: Asn1OctetString) -> Result<Self, Asn1Error> {
        if private_key.as_bytes().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            private_key,
            parameters: None,
            public_key: None,
        })
    }

    /// Attaches parameters without checking their relationship to the key.
    /// Variable time: branches only on the encoding structure.
    /// Private key octets are copied without branching on their values, only their public length.
    pub fn with_parameters(mut self, parameters: X962Parameters) -> Self {
        self.parameters = Some(parameters);
        self
    }

    /// Attaches public key bits without checking their relationship to the private key.
    /// Variable time: branches only on the encoding structure.
    /// Private key octets are copied without branching on their values, only their public length.
    pub fn with_public_key(mut self, public_key: Asn1BitString) -> Self {
        self.public_key = Some(public_key);
        self
    }

    /// Borrows the private key octets; the caller must protect them.
    /// Variable time: branches only on the encoding structure.
    /// Private key octets are copied without branching on their values, only their public length.
    pub fn private_key(&self) -> &Asn1OctetString {
        &self.private_key
    }

    /// Moves the private key octets out without cloning them.
    /// Variable time: branches only on the encoding structure.
    /// Private key octets are copied without branching on their values, only their public length.
    pub fn into_private_key(self) -> Asn1OctetString {
        self.private_key
    }

    /// Returns the optional domain parameters.
    /// Variable time: branches only on the encoding structure.
    /// Private key octets are copied without branching on their values, only their public length.
    pub fn parameters(&self) -> Option<&X962Parameters> {
        self.parameters.as_ref()
    }

    /// Returns the optional public key.
    /// Variable time: branches only on the encoding structure.
    /// Private key octets are copied without branching on their values, only their public length.
    pub fn public_key(&self) -> Option<&Asn1BitString> {
        self.public_key.as_ref()
    }
}

struct RedactedKeyLength(usize);

impl fmt::Debug for RedactedKeyLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted, {} octets>", self.0)
    }
}

impl fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcPrivateKey")
            .field(
                "private_key",
                &RedactedKeyLength(self.private_key.as_bytes().len()),
            )
            .field("parameters", &self.parameters)
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl DecodeInner for EcPrivateKey {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        if fields.get::<Asn1Integer>()?.as_bytes() != [1] {
            return Err(Asn1Error::MalformedValue);
        }
        let private_key = fields.get()?;
        let parameters = fields.get_explicit_opt::<X962Parameters>([0xa0])?;
        let public_key = fields.get_explicit_opt::<Asn1BitString>([0xa1])?;
        fields.end()?;
        let mut value = Self::new(private_key)?;
        value.parameters = parameters;
        value.public_key = public_key;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for EcPrivateKey {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        3 + self.private_key.encoded_len(rules)
            + self
                .parameters
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .public_key
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out.get_mut(..3)
            .ok_or(Asn1Error::BufferTooSmall)?
            .copy_from_slice(&[2, 1, 1]);
        let mut at = 3;
        at += self.private_key.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.parameters {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.public_key {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for EcPrivateKey {}

impl Tagged for EcPrivateKey {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EcPrivateKey {}

impl Encode for EcPrivateKey {
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
    use alloc::{format, vec};

    use tc_asn1::{
        Asn1BitString, Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    use super::EcPrivateKey;
    use crate::{EcNamedCurve, X962Parameters};

    #[test]
    fn the_rfc_5915_shaped_fixture_round_trips_with_explicit_optional_fields() {
        let mut point = vec![0x04];
        point.extend_from_slice(&[0x22; 64]);
        let value = EcPrivateKey::new(Asn1OctetString::new(&[0x11; 32]))
            .unwrap()
            .with_parameters(EcNamedCurve::PRIME256V1.oid().into())
            .with_public_key(Asn1BitString::from_bytes(&point));
        let mut wire = vec![0x30, 0x77, 2, 1, 1, 4, 0x20];
        wire.extend_from_slice(&[0x11; 32]);
        wire.extend_from_slice(&[
            0xa0, 0x0a, 6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7, 0xa1, 0x44, 3, 0x42, 0,
        ]);
        wire.extend_from_slice(&point);
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            EcPrivateKey::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
        assert_eq!(
            EcPrivateKey::decode(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn every_combination_of_private_key_optional_fields_round_trips() {
        for parameters in [false, true] {
            for public in [false, true] {
                let mut value = EcPrivateKey::new(Asn1OctetString::new(&[1])).unwrap();
                if parameters {
                    value = value.with_parameters(X962Parameters::ImplicitlyCa);
                }
                if public {
                    value = value.with_public_key(Asn1BitString::from_bytes(&[4, 1, 2]));
                }
                for rules in [
                    EncodingOptions::BER,
                    EncodingOptions::DER,
                    EncodingOptions::CER,
                ] {
                    let wire = value.encode_to_vec(&rules).unwrap();
                    assert_eq!(
                        EcPrivateKey::decode(&wire, &DecodingOptions::default())
                            .unwrap()
                            .1,
                        value
                    );
                }
            }
        }
    }

    #[test]
    fn empty_private_keys_wrong_versions_and_wrong_optional_order_are_rejected() {
        assert_eq!(
            EcPrivateKey::new(Asn1OctetString::new(&[])),
            Err(Asn1Error::MalformedValue)
        );
        for (wire, error) in [
            (
                &b"\x30\x05\x02\x01\x01\x04\x00"[..],
                Asn1Error::MalformedValue,
            ),
            (
                &b"\x30\x06\x02\x01\x00\x04\x01\x01"[..],
                Asn1Error::MalformedValue,
            ),
            (
                &b"\x30\x0f\x02\x01\x01\x04\x01\x01\xa1\x03\x03\x01\x00\xa0\x02\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
            // Raw OID contents for 0.4.0, rather than an OID TLV inside [0].
            (
                &b"\x30\x0a\x02\x01\x01\x04\x01\x01\xa0\x02\x04\x00"[..],
                Asn1Error::UnexpectedTag,
            ),
            (&b"\x30\x03\x02\x01\x01"[..], Asn1Error::Truncated),
        ] {
            assert_eq!(
                EcPrivateKey::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }

    #[test]
    fn debug_redacts_key_octets_and_extraction_moves_the_original_buffer() {
        let value = EcPrivateKey::new(Asn1OctetString::new(&[0x11; 32])).unwrap();
        assert_eq!(
            format!("{value:?}"),
            "EcPrivateKey { private_key: <redacted, 32 octets>, parameters: None, public_key: None }"
        );
        assert!(!format!("{value:#?}").contains("17,"));
        let pointer = value.private_key().as_bytes().as_ptr();
        let key = value.into_private_key();
        assert_eq!(key.as_bytes().as_ptr(), pointer);
    }
}
