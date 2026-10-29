//! PKCS #12 (RFC 7292) bag types and password-based encryption schemes.
//!
//! This table names known algorithms without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// The PKCS #12 safe-bag types and its PBE schemes, keyed by the PKCS #12 KDF.
///
/// ```
/// use tc_asn1_pkcs::Pkcs12Algorithm;
///
/// assert_eq!(Pkcs12Algorithm::PKCS8_SHROUDED_KEY_BAG.dotted(), "1.2.840.113549.1.12.10.1.2");
/// assert_eq!(
///     Pkcs12Algorithm::from_oid(&Pkcs12Algorithm::KEY_BAG.oid()),
///     Some(Pkcs12Algorithm::KEY_BAG),
/// );
/// ```
pub struct Pkcs12Algorithm;

impl Pkcs12Algorithm {
    /// A PKCS #8 private key in the clear.
    pub const KEY_BAG: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x01,
        ],
        "1.2.840.113549.1.12.10.1.1",
        "keyBag",
    );

    /// A PKCS #8 encrypted private key.
    pub const PKCS8_SHROUDED_KEY_BAG: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02,
        ],
        "1.2.840.113549.1.12.10.1.2",
        "pkcs8ShroudedKeyBag",
    );

    /// A certificate.
    pub const CERT_BAG: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03,
        ],
        "1.2.840.113549.1.12.10.1.3",
        "certBag",
    );

    /// A CRL.
    pub const CRL_BAG: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x04,
        ],
        "1.2.840.113549.1.12.10.1.4",
        "crlBag",
    );

    /// A secret of a user-defined type.
    pub const SECRET_BAG: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x05,
        ],
        "1.2.840.113549.1.12.10.1.5",
        "secretBag",
    );

    /// Nested safe contents.
    pub const SAFE_CONTENTS_BAG: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x06,
        ],
        "1.2.840.113549.1.12.10.1.6",
        "safeContentsBag",
    );

    /// RC4 with a 128-bit key.
    pub const PBE_WITH_SHA_AND_128_BIT_RC4: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x01],
        "1.2.840.113549.1.12.1.1",
        "pbeWithSHAAnd128BitRC4",
    );

    /// RC4 with a 40-bit key.
    pub const PBE_WITH_SHA_AND_40_BIT_RC4: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x02],
        "1.2.840.113549.1.12.1.2",
        "pbeWithSHAAnd40BitRC4",
    );

    /// Three-key Triple DES in CBC mode.
    pub const PBE_WITH_SHA_AND_3_KEY_TRIPLE_DES_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03],
        "1.2.840.113549.1.12.1.3",
        "pbeWithSHAAnd3-KeyTripleDES-CBC",
    );

    /// Two-key Triple DES in CBC mode.
    pub const PBE_WITH_SHA_AND_2_KEY_TRIPLE_DES_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x04],
        "1.2.840.113549.1.12.1.4",
        "pbeWithSHAAnd2-KeyTripleDES-CBC",
    );

    /// RC2 with a 128-bit key in CBC mode.
    pub const PBE_WITH_SHA_AND_128_BIT_RC2_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x05],
        "1.2.840.113549.1.12.1.5",
        "pbeWithSHAAnd128BitRC2-CBC",
    );

    /// RC2 with a 40-bit key in CBC mode.
    pub const PBE_WITH_SHA_AND_40_BIT_RC2_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x06],
        "1.2.840.113549.1.12.1.6",
        "pbewithSHAAnd40BitRC2-CBC",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::KEY_BAG,
        Self::PKCS8_SHROUDED_KEY_BAG,
        Self::CERT_BAG,
        Self::CRL_BAG,
        Self::SECRET_BAG,
        Self::SAFE_CONTENTS_BAG,
        Self::PBE_WITH_SHA_AND_128_BIT_RC4,
        Self::PBE_WITH_SHA_AND_40_BIT_RC4,
        Self::PBE_WITH_SHA_AND_3_KEY_TRIPLE_DES_CBC,
        Self::PBE_WITH_SHA_AND_2_KEY_TRIPLE_DES_CBC,
        Self::PBE_WITH_SHA_AND_128_BIT_RC2_CBC,
        Self::PBE_WITH_SHA_AND_40_BIT_RC2_CBC,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
