//! RFC 8017 algorithm and digest object identifiers.
//!
//! This table names known algorithms without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// PKCS#1 algorithm names and the digest identifiers used by their parameters.
///
/// ```
/// use tc_asn1_pkcs::Pkcs1Algorithm;
///
/// assert_eq!(Pkcs1Algorithm::RSA_ENCRYPTION.dotted(), "1.2.840.113549.1.1.1");
/// assert_eq!(
///     Pkcs1Algorithm::from_oid(&Pkcs1Algorithm::MGF1.oid()),
///     Some(Pkcs1Algorithm::MGF1),
/// );
/// ```
pub struct Pkcs1Algorithm;

impl Pkcs1Algorithm {
    /// The rsaEncryption identifier.
    pub const RSA_ENCRYPTION: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
        "1.2.840.113549.1.1.1",
        "rsaEncryption",
    );

    /// The id-RSAES-OAEP identifier.
    pub const RSAES_OAEP: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07],
        "1.2.840.113549.1.1.7",
        "id-RSAES-OAEP",
    );

    /// The id-mgf1 identifier.
    pub const MGF1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08],
        "1.2.840.113549.1.1.8",
        "id-mgf1",
    );

    /// The id-pSpecified identifier.
    pub const P_SPECIFIED: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x09],
        "1.2.840.113549.1.1.9",
        "id-pSpecified",
    );

    /// The id-RSASSA-PSS identifier.
    pub const RSASSA_PSS: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a],
        "1.2.840.113549.1.1.10",
        "id-RSASSA-PSS",
    );

    /// The md5WithRSAEncryption identifier.
    pub const MD5_WITH_RSA_ENCRYPTION: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04],
        "1.2.840.113549.1.1.4",
        "md5WithRSAEncryption",
    );

    /// The sha1WithRSAEncryption identifier.
    pub const SHA1_WITH_RSA_ENCRYPTION: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05],
        "1.2.840.113549.1.1.5",
        "sha1WithRSAEncryption",
    );

    /// The sha256WithRSAEncryption identifier.
    pub const SHA256_WITH_RSA_ENCRYPTION: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
        "1.2.840.113549.1.1.11",
        "sha256WithRSAEncryption",
    );

    /// The sha384WithRSAEncryption identifier.
    pub const SHA384_WITH_RSA_ENCRYPTION: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c],
        "1.2.840.113549.1.1.12",
        "sha384WithRSAEncryption",
    );

    /// The sha512WithRSAEncryption identifier.
    pub const SHA512_WITH_RSA_ENCRYPTION: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d],
        "1.2.840.113549.1.1.13",
        "sha512WithRSAEncryption",
    );

    /// The sha224WithRSAEncryption identifier.
    pub const SHA224_WITH_RSA_ENCRYPTION: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e],
        "1.2.840.113549.1.1.14",
        "sha224WithRSAEncryption",
    );

    /// The sha512-224WithRSAEncryption identifier.
    pub const SHA512_224_WITH_RSA_ENCRYPTION: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0f],
        "1.2.840.113549.1.1.15",
        "sha512-224WithRSAEncryption",
    );

    /// The sha512-256WithRSAEncryption identifier.
    pub const SHA512_256_WITH_RSA_ENCRYPTION: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x10],
        "1.2.840.113549.1.1.16",
        "sha512-256WithRSAEncryption",
    );

    /// The id-sha1 identifier.
    pub const SHA1: NamedOid =
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x1a], "1.3.14.3.2.26", "id-sha1");

    /// The id-sha224 identifier.
    pub const SHA224: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
        "2.16.840.1.101.3.4.2.4",
        "id-sha224",
    );

    /// The id-sha256 identifier.
    pub const SHA256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        "2.16.840.1.101.3.4.2.1",
        "id-sha256",
    );

    /// The id-sha384 identifier.
    pub const SHA384: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
        "2.16.840.1.101.3.4.2.2",
        "id-sha384",
    );

    /// The id-sha512 identifier.
    pub const SHA512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
        "2.16.840.1.101.3.4.2.3",
        "id-sha512",
    );

    /// All distinct identifiers named by this table.
    pub const ALL: &'static [NamedOid] = &[
        Self::RSA_ENCRYPTION,
        Self::RSAES_OAEP,
        Self::MGF1,
        Self::P_SPECIFIED,
        Self::RSASSA_PSS,
        Self::MD5_WITH_RSA_ENCRYPTION,
        Self::SHA1_WITH_RSA_ENCRYPTION,
        Self::SHA256_WITH_RSA_ENCRYPTION,
        Self::SHA384_WITH_RSA_ENCRYPTION,
        Self::SHA512_WITH_RSA_ENCRYPTION,
        Self::SHA224_WITH_RSA_ENCRYPTION,
        Self::SHA512_224_WITH_RSA_ENCRYPTION,
        Self::SHA512_256_WITH_RSA_ENCRYPTION,
        Self::SHA1,
        Self::SHA224,
        Self::SHA256,
        Self::SHA384,
        Self::SHA512,
    ];

    /// Finds the standard name for an identifier, if known.
    /// Variable time: branches only on the encoding structure.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use tc_asn1::{Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::Pkcs1Algorithm;

    #[test]
    fn every_pkcs1_identifier_matches_its_dotted_form_and_lookup_name() {
        for entry in Pkcs1Algorithm::ALL {
            let parsed: Asn1Oid = entry.dotted().parse().unwrap();
            assert_eq!(parsed, entry.oid());
            assert_eq!(entry.oid().to_string(), entry.dotted());
            let wire = entry.oid().encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                Asn1Oid::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                parsed
            );
            assert_eq!(Pkcs1Algorithm::from_oid(&parsed), Some(*entry));
        }
        assert_eq!(Pkcs1Algorithm::from_oid(&"1.2.3.4".parse().unwrap()), None);
    }

    #[test]
    fn the_pkcs1_table_contains_no_duplicate_identifiers_or_names() {
        for (i, a) in Pkcs1Algorithm::ALL.iter().enumerate() {
            for b in &Pkcs1Algorithm::ALL[i + 1..] {
                assert_ne!(a.oid(), b.oid());
                assert_ne!(a.name(), b.name());
            }
        }
    }
}
