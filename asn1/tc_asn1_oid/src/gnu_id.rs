//! GNU and GnuPG algorithm identifiers, as Bouncy Castle's
//! `GnuObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// GNU and GnuPG algorithm identifiers.
///
/// ```
/// use tc_asn1_oid::GnuId;
///
/// assert_eq!(GnuId::GNU_PG.dotted(), "1.3.6.1.4.1.11591.2");
/// assert_eq!(
///     GnuId::from_oid(&GnuId::GNU_PG.oid()),
///     Some(GnuId::GNU_PG),
/// );
/// ```
pub struct GnuId;

impl GnuId {
    /// Bouncy Castle's `Gnu`.
    pub const GNU: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x01],
        "1.3.6.1.4.1.11591.1",
        "Gnu",
    );

    /// Bouncy Castle's `GnuPG`.
    pub const GNU_PG: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x02],
        "1.3.6.1.4.1.11591.2",
        "GnuPG",
    );

    /// Bouncy Castle's `Notation`.
    pub const NOTATION: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x02, 0x01],
        "1.3.6.1.4.1.11591.2.1",
        "Notation",
    );

    /// Bouncy Castle's `PkaAddress`.
    pub const PKA_ADDRESS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x02, 0x01, 0x01],
        "1.3.6.1.4.1.11591.2.1.1",
        "PkaAddress",
    );

    /// Bouncy Castle's `GnuRadar`.
    pub const GNU_RADAR: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x03],
        "1.3.6.1.4.1.11591.3",
        "GnuRadar",
    );

    /// Bouncy Castle's `DigestAlgorithm`.
    pub const DIGEST_ALGORITHM: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0c],
        "1.3.6.1.4.1.11591.12",
        "DigestAlgorithm",
    );

    /// Bouncy Castle's `Tiger192`.
    pub const TIGER192: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0c, 0x02],
        "1.3.6.1.4.1.11591.12.2",
        "Tiger192",
    );

    /// Bouncy Castle's `EncryptionAlgorithm`.
    pub const ENCRYPTION_ALGORITHM: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d],
        "1.3.6.1.4.1.11591.13",
        "EncryptionAlgorithm",
    );

    /// Bouncy Castle's `Serpent`.
    pub const SERPENT: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02],
        "1.3.6.1.4.1.11591.13.2",
        "Serpent",
    );

    /// Bouncy Castle's `Serpent128Ecb`.
    pub const SERPENT128_ECB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02, 0x01],
        "1.3.6.1.4.1.11591.13.2.1",
        "Serpent128Ecb",
    );

    /// Bouncy Castle's `Serpent128Cbc`.
    pub const SERPENT128_CBC: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02, 0x02],
        "1.3.6.1.4.1.11591.13.2.2",
        "Serpent128Cbc",
    );

    /// Bouncy Castle's `Serpent128Ofb`.
    pub const SERPENT128_OFB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02, 0x03],
        "1.3.6.1.4.1.11591.13.2.3",
        "Serpent128Ofb",
    );

    /// Bouncy Castle's `Serpent128Cfb`.
    pub const SERPENT128_CFB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02, 0x04],
        "1.3.6.1.4.1.11591.13.2.4",
        "Serpent128Cfb",
    );

    /// Bouncy Castle's `Serpent192Ecb`.
    pub const SERPENT192_ECB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02, 0x15],
        "1.3.6.1.4.1.11591.13.2.21",
        "Serpent192Ecb",
    );

    /// Bouncy Castle's `Serpent192Cbc`.
    pub const SERPENT192_CBC: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02, 0x16],
        "1.3.6.1.4.1.11591.13.2.22",
        "Serpent192Cbc",
    );

    /// Bouncy Castle's `Serpent192Ofb`.
    pub const SERPENT192_OFB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02, 0x17],
        "1.3.6.1.4.1.11591.13.2.23",
        "Serpent192Ofb",
    );

    /// Bouncy Castle's `Serpent192Cfb`.
    pub const SERPENT192_CFB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02, 0x18],
        "1.3.6.1.4.1.11591.13.2.24",
        "Serpent192Cfb",
    );

    /// Bouncy Castle's `Serpent256Ecb`.
    pub const SERPENT256_ECB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02, 0x29],
        "1.3.6.1.4.1.11591.13.2.41",
        "Serpent256Ecb",
    );

    /// Bouncy Castle's `Serpent256Cbc`.
    pub const SERPENT256_CBC: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02, 0x2a],
        "1.3.6.1.4.1.11591.13.2.42",
        "Serpent256Cbc",
    );

    /// Bouncy Castle's `Serpent256Ofb`.
    pub const SERPENT256_OFB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02, 0x2b],
        "1.3.6.1.4.1.11591.13.2.43",
        "Serpent256Ofb",
    );

    /// Bouncy Castle's `Serpent256Cfb`.
    pub const SERPENT256_CFB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0d, 0x02, 0x2c],
        "1.3.6.1.4.1.11591.13.2.44",
        "Serpent256Cfb",
    );

    /// Bouncy Castle's `Crc`.
    pub const CRC: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0e],
        "1.3.6.1.4.1.11591.14",
        "Crc",
    );

    /// Bouncy Castle's `Crc32`.
    pub const CRC32: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0e, 0x01],
        "1.3.6.1.4.1.11591.14.1",
        "Crc32",
    );

    /// Bouncy Castle's `EllipticCurve`.
    pub const ELLIPTIC_CURVE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f],
        "1.3.6.1.4.1.11591.15",
        "EllipticCurve",
    );

    /// Bouncy Castle's `Ed25519`.
    pub const ED25519: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01],
        "1.3.6.1.4.1.11591.15.1",
        "Ed25519",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::GNU,
        Self::GNU_PG,
        Self::NOTATION,
        Self::PKA_ADDRESS,
        Self::GNU_RADAR,
        Self::DIGEST_ALGORITHM,
        Self::TIGER192,
        Self::ENCRYPTION_ALGORITHM,
        Self::SERPENT,
        Self::SERPENT128_ECB,
        Self::SERPENT128_CBC,
        Self::SERPENT128_OFB,
        Self::SERPENT128_CFB,
        Self::SERPENT192_ECB,
        Self::SERPENT192_CBC,
        Self::SERPENT192_OFB,
        Self::SERPENT192_CFB,
        Self::SERPENT256_ECB,
        Self::SERPENT256_CBC,
        Self::SERPENT256_OFB,
        Self::SERPENT256_CFB,
        Self::CRC,
        Self::CRC32,
        Self::ELLIPTIC_CURVE,
        Self::ED25519,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
