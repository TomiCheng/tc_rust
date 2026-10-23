//! RFC 8018 key derivation, encryption scheme and PRF object identifiers.
//!
//! This table names known algorithms without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// PKCS#5 v2 algorithm names and the HMAC PRFs PBKDF2 takes.
///
/// ```
/// use tc_asn1_pkcs::Pkcs5Algorithm;
///
/// assert_eq!(Pkcs5Algorithm::PBES2.dotted(), "1.2.840.113549.1.5.13");
/// assert_eq!(
///     Pkcs5Algorithm::from_oid(&Pkcs5Algorithm::HMAC_WITH_SHA256.oid()),
///     Some(Pkcs5Algorithm::HMAC_WITH_SHA256),
/// );
/// ```
pub struct Pkcs5Algorithm;

impl Pkcs5Algorithm {
    /// The id-PBKDF2 identifier.
    pub const PBKDF2: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c],
        "1.2.840.113549.1.5.12",
        "id-PBKDF2",
    );

    /// The id-PBES2 identifier.
    pub const PBES2: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d],
        "1.2.840.113549.1.5.13",
        "id-PBES2",
    );

    /// The id-hmacWithSHA1 identifier, the default PBKDF2 PRF.
    pub const HMAC_WITH_SHA1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07],
        "1.2.840.113549.2.7",
        "id-hmacWithSHA1",
    );

    /// The id-hmacWithSHA224 identifier.
    pub const HMAC_WITH_SHA224: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08],
        "1.2.840.113549.2.8",
        "id-hmacWithSHA224",
    );

    /// The id-hmacWithSHA256 identifier.
    pub const HMAC_WITH_SHA256: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09],
        "1.2.840.113549.2.9",
        "id-hmacWithSHA256",
    );

    /// The id-hmacWithSHA384 identifier.
    pub const HMAC_WITH_SHA384: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a],
        "1.2.840.113549.2.10",
        "id-hmacWithSHA384",
    );

    /// The id-hmacWithSHA512 identifier.
    pub const HMAC_WITH_SHA512: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b],
        "1.2.840.113549.2.11",
        "id-hmacWithSHA512",
    );

    /// The id-hmacWithSHA512-224 identifier.
    pub const HMAC_WITH_SHA512_224: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0c],
        "1.2.840.113549.2.12",
        "id-hmacWithSHA512-224",
    );

    /// The id-hmacWithSHA512-256 identifier.
    pub const HMAC_WITH_SHA512_256: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0d],
        "1.2.840.113549.2.13",
        "id-hmacWithSHA512-256",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::PBKDF2,
        Self::PBES2,
        Self::HMAC_WITH_SHA1,
        Self::HMAC_WITH_SHA224,
        Self::HMAC_WITH_SHA256,
        Self::HMAC_WITH_SHA384,
        Self::HMAC_WITH_SHA512,
        Self::HMAC_WITH_SHA512_224,
        Self::HMAC_WITH_SHA512_256,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use tc_asn1::Asn1Oid;

    use super::Pkcs5Algorithm;

    #[test]
    fn every_pkcs5_identifier_matches_its_dotted_form_and_lookup_name() {
        for entry in Pkcs5Algorithm::ALL {
            let parsed: Asn1Oid = entry.dotted().parse().unwrap();
            assert_eq!(parsed, entry.oid());
            assert_eq!(entry.oid().to_string(), entry.dotted());
            assert_eq!(Pkcs5Algorithm::from_oid(&parsed), Some(*entry));
        }
        assert_eq!(Pkcs5Algorithm::from_oid(&"1.2.3.4".parse().unwrap()), None);
    }
}
