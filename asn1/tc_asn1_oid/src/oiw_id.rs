//! OIW secsig algorithm identifiers, as Bouncy Castle's `OiwObjectIdentifiers`
//! names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// OIW secsig algorithm identifiers.
///
/// ```
/// use tc_asn1_oid::OiwId;
///
/// assert_eq!(OiwId::MD5_WITH_RSA.dotted(), "1.3.14.3.2.3");
/// assert_eq!(
///     OiwId::from_oid(&OiwId::MD5_WITH_RSA.oid()),
///     Some(OiwId::MD5_WITH_RSA),
/// );
/// ```
pub struct OiwId;

impl OiwId {
    /// Bouncy Castle's `MD4WithRsa`.
    pub const MD4_WITH_RSA: NamedOid = NamedOid::new(
        &[0x2b, 0x0e, 0x03, 0x02, 0x02],
        "1.3.14.3.2.2",
        "MD4WithRsa",
    );

    /// Bouncy Castle's `MD5WithRsa`.
    pub const MD5_WITH_RSA: NamedOid = NamedOid::new(
        &[0x2b, 0x0e, 0x03, 0x02, 0x03],
        "1.3.14.3.2.3",
        "MD5WithRsa",
    );

    /// Bouncy Castle's `MD4WithRsaEncryption`.
    pub const MD4_WITH_RSA_ENCRYPTION: NamedOid = NamedOid::new(
        &[0x2b, 0x0e, 0x03, 0x02, 0x04],
        "1.3.14.3.2.4",
        "MD4WithRsaEncryption",
    );

    /// Bouncy Castle's `DesEcb`.
    pub const DES_ECB: NamedOid =
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x06], "1.3.14.3.2.6", "DesEcb");

    /// Bouncy Castle's `DesCbc`.
    pub const DES_CBC: NamedOid =
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x07], "1.3.14.3.2.7", "DesCbc");

    /// Bouncy Castle's `DesOfb`.
    pub const DES_OFB: NamedOid =
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x08], "1.3.14.3.2.8", "DesOfb");

    /// Bouncy Castle's `DesCfb`.
    pub const DES_CFB: NamedOid =
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x09], "1.3.14.3.2.9", "DesCfb");

    /// Bouncy Castle's `DesEde`.
    pub const DES_EDE: NamedOid =
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x11], "1.3.14.3.2.17", "DesEde");

    /// Bouncy Castle's `IdSha1`.
    pub const ID_SHA1: NamedOid =
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x1a], "1.3.14.3.2.26", "IdSha1");

    /// Bouncy Castle's `DsaWithSha1`.
    pub const DSA_WITH_SHA1: NamedOid = NamedOid::new(
        &[0x2b, 0x0e, 0x03, 0x02, 0x1b],
        "1.3.14.3.2.27",
        "DsaWithSha1",
    );

    /// Bouncy Castle's `Sha1WithRsa`.
    pub const SHA1_WITH_RSA: NamedOid = NamedOid::new(
        &[0x2b, 0x0e, 0x03, 0x02, 0x1d],
        "1.3.14.3.2.29",
        "Sha1WithRsa",
    );

    /// Bouncy Castle's `ElGamalAlgorithm`.
    pub const ELGAMAL_ALGORITHM: NamedOid = NamedOid::new(
        &[0x2b, 0x0e, 0x07, 0x02, 0x01, 0x01],
        "1.3.14.7.2.1.1",
        "ElGamalAlgorithm",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::MD4_WITH_RSA,
        Self::MD5_WITH_RSA,
        Self::MD4_WITH_RSA_ENCRYPTION,
        Self::DES_ECB,
        Self::DES_CBC,
        Self::DES_OFB,
        Self::DES_CFB,
        Self::DES_EDE,
        Self::ID_SHA1,
        Self::DSA_WITH_SHA1,
        Self::SHA1_WITH_RSA,
        Self::ELGAMAL_ALGORITHM,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
