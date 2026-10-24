//! X9 algorithm and scheme object identifiers: X9.62 EC keys and ECDSA,
//! X9.57 DSA, X9.42 Diffie-Hellman and X9.63 key-agreement schemes.
//!
//! Field, basis and named-curve identifiers stay with [`crate::FieldId`],
//! [`crate::CharacteristicTwo`] and [`crate::EcNamedCurve`].

use tc_asn1::{Asn1Oid, NamedOid};

/// X9 algorithm constants and lookup, as Bouncy Castle's `X9ObjectIdentifiers`.
///
/// ```
/// use tc_asn1::{Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::X9Algorithm;
///
/// let der = X9Algorithm::DH_PUBLIC_NUMBER.oid().encode_to_vec(&EncodingOptions::DER)?;
/// let back = Asn1Oid::decode_der(&der, &DecodingOptions::default())?.1;
/// assert_eq!(X9Algorithm::from_oid(&back), Some(X9Algorithm::DH_PUBLIC_NUMBER));
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct X9Algorithm;

impl X9Algorithm {
    /// The X9.62 elliptic-curve public key type, `id-ecPublicKey`.
    pub const ID_EC_PUBLIC_KEY: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
        "1.2.840.10045.2.1",
        "id-ecPublicKey",
    );

    /// ECDSA with SHA-1.
    pub const ECDSA_WITH_SHA1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01],
        "1.2.840.10045.4.1",
        "ecdsa-with-SHA1",
    );

    /// ECDSA with SHA-224.
    pub const ECDSA_WITH_SHA224: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01],
        "1.2.840.10045.4.3.1",
        "ecdsa-with-SHA224",
    );

    /// ECDSA with SHA-256.
    pub const ECDSA_WITH_SHA256: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
        "1.2.840.10045.4.3.2",
        "ecdsa-with-SHA256",
    );

    /// ECDSA with SHA-384.
    pub const ECDSA_WITH_SHA384: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03],
        "1.2.840.10045.4.3.3",
        "ecdsa-with-SHA384",
    );

    /// ECDSA with SHA-512.
    pub const ECDSA_WITH_SHA512: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04],
        "1.2.840.10045.4.3.4",
        "ecdsa-with-SHA512",
    );

    /// The X9.57 DSA public key type.
    pub const ID_DSA: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01],
        "1.2.840.10040.4.1",
        "id-dsa",
    );

    /// DSA with SHA-1.
    pub const ID_DSA_WITH_SHA1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03],
        "1.2.840.10040.4.3",
        "id-dsa-with-sha1",
    );

    /// The X9.42 Diffie-Hellman public key type, whose parameters are
    /// [`DomainParameters`](crate::DomainParameters).
    pub const DH_PUBLIC_NUMBER: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01],
        "1.2.840.10046.2.1",
        "dhpublicnumber",
    );

    /// The X9.42 static Diffie-Hellman scheme.
    pub const DH_STATIC: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x03, 0x01],
        "1.2.840.10046.2.3.1",
        "dhStatic",
    );

    /// The X9.42 ephemeral Diffie-Hellman scheme.
    pub const DH_EPHEM: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x03, 0x02],
        "1.2.840.10046.2.3.2",
        "dhEphem",
    );

    /// The X9.42 one-flow Diffie-Hellman scheme.
    pub const DH_ONE_FLOW: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x03, 0x03],
        "1.2.840.10046.2.3.3",
        "dhOneFlow",
    );

    /// The X9.42 first hybrid Diffie-Hellman scheme.
    pub const DH_HYBRID1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x03, 0x04],
        "1.2.840.10046.2.3.4",
        "dhHybrid1",
    );

    /// The X9.42 second hybrid Diffie-Hellman scheme.
    pub const DH_HYBRID2: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x03, 0x05],
        "1.2.840.10046.2.3.5",
        "dhHybrid2",
    );

    /// The X9.42 one-flow hybrid Diffie-Hellman scheme.
    pub const DH_HYBRID_ONE_FLOW: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x03, 0x06],
        "1.2.840.10046.2.3.6",
        "dhHybridOneFlow",
    );

    /// The X9.42 two-pass MQV scheme.
    pub const MQV2: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x03, 0x07],
        "1.2.840.10046.2.3.7",
        "mqv2",
    );

    /// The X9.42 one-pass MQV scheme.
    pub const MQV1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x03, 0x08],
        "1.2.840.10046.2.3.8",
        "mqv1",
    );

    /// The X9.63 single-pass standard ECDH scheme with the SHA-1 KDF.
    pub const DH_SINGLE_PASS_STD_DH_SHA1_KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x05, 0x10, 0x86, 0x48, 0x3f, 0x00, 0x02],
        "1.3.133.16.840.63.0.2",
        "dhSinglePass-stdDH-sha1kdf-scheme",
    );

    /// The X9.63 single-pass cofactor ECDH scheme with the SHA-1 KDF.
    pub const DH_SINGLE_PASS_COFACTOR_DH_SHA1_KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x05, 0x10, 0x86, 0x48, 0x3f, 0x00, 0x03],
        "1.3.133.16.840.63.0.3",
        "dhSinglePass-cofactorDH-sha1kdf-scheme",
    );

    /// The X9.63 single-pass ECMQV scheme with the SHA-1 KDF.
    pub const MQV_SINGLE_PASS_SHA1_KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x05, 0x10, 0x86, 0x48, 0x3f, 0x00, 0x10],
        "1.3.133.16.840.63.0.16",
        "mqvSinglePass-sha1kdf-scheme",
    );

    /// All 20 identifiers.
    pub const ALL: &'static [NamedOid] = &[
        Self::ID_EC_PUBLIC_KEY,
        Self::ECDSA_WITH_SHA1,
        Self::ECDSA_WITH_SHA224,
        Self::ECDSA_WITH_SHA256,
        Self::ECDSA_WITH_SHA384,
        Self::ECDSA_WITH_SHA512,
        Self::ID_DSA,
        Self::ID_DSA_WITH_SHA1,
        Self::DH_PUBLIC_NUMBER,
        Self::DH_STATIC,
        Self::DH_EPHEM,
        Self::DH_ONE_FLOW,
        Self::DH_HYBRID1,
        Self::DH_HYBRID2,
        Self::DH_HYBRID_ONE_FLOW,
        Self::MQV2,
        Self::MQV1,
        Self::DH_SINGLE_PASS_STD_DH_SHA1_KDF_SCHEME,
        Self::DH_SINGLE_PASS_COFACTOR_DH_SHA1_KDF_SCHEME,
        Self::MQV_SINGLE_PASS_SHA1_KDF_SCHEME,
    ];

    /// Returns the table entry, or None for an identifier outside it.
    /// Variable time: branches only on the encoding structure.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use tc_asn1::{Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::X9Algorithm;

    #[test]
    fn every_algorithm_encodes_its_dotted_oid_and_is_found_again() {
        assert_eq!(X9Algorithm::ALL.len(), 20);
        for entry in X9Algorithm::ALL {
            let oid: Asn1Oid = entry.dotted().parse().unwrap();
            assert_eq!(entry.oid(), oid, "{}", entry.dotted());
            let wire = oid.encode_to_vec(&EncodingOptions::DER).unwrap();
            let back = Asn1Oid::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1;
            assert_eq!(back.to_string(), entry.dotted());
            assert_eq!(X9Algorithm::from_oid(&back), Some(*entry));
        }
    }

    #[test]
    fn algorithm_entries_have_unique_oids_and_unknown_oids_return_none() {
        for (i, a) in X9Algorithm::ALL.iter().enumerate() {
            for b in &X9Algorithm::ALL[..i] {
                assert_ne!(a.oid(), b.oid());
            }
        }
        assert_eq!(
            X9Algorithm::from_oid(&"1.2.840.10045.3.1.7".parse().unwrap()),
            None
        );
    }
}
