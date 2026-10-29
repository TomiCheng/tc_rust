//! S/MIME capability identifiers, as Bouncy Castle's `SmimeCapability` names
//! them: general preferences and content encryption algorithms.
//!
//! This table names known capabilities without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// Identifiers for an `SmimeCapability`.
///
/// ```
/// use tc_asn1_ess::SmimeCapabilityId;
///
/// assert_eq!(SmimeCapabilityId::DES_EDE3_CBC.dotted(), "1.2.840.113549.3.7");
/// assert_eq!(
///     SmimeCapabilityId::from_oid(&SmimeCapabilityId::PREFER_SIGNED_DATA.oid()),
///     Some(SmimeCapabilityId::PREFER_SIGNED_DATA),
/// );
/// ```
pub struct SmimeCapabilityId;

impl SmimeCapabilityId {
    /// Prefers signed data over other content types.
    pub const PREFER_SIGNED_DATA: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0f, 0x01],
        "1.2.840.113549.1.9.15.1",
        "preferSignedData",
    );

    /// Cannot decrypt any encrypted content.
    pub const CANNOT_DECRYPT_ANY: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0f, 0x02],
        "1.2.840.113549.1.9.15.2",
        "canNotDecryptAny",
    );

    /// The S/MIME versions supported.
    pub const SMIME_CAPABILITIES_VERSIONS: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0f, 0x03],
        "1.2.840.113549.1.9.15.3",
        "sMIMECapabilitiesVersions",
    );

    /// AES-256 in CBC mode.
    pub const AES256_CBC: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a],
        "2.16.840.1.101.3.4.1.42",
        "id-aes256-CBC",
    );

    /// AES-192 in CBC mode.
    pub const AES192_CBC: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16],
        "2.16.840.1.101.3.4.1.22",
        "id-aes192-CBC",
    );

    /// AES-128 in CBC mode.
    pub const AES128_CBC: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02],
        "2.16.840.1.101.3.4.1.2",
        "id-aes128-CBC",
    );

    /// IDEA in CBC mode.
    pub const IDEA_CBC: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x3c, 0x07, 0x01, 0x01, 0x02,
        ],
        "1.3.6.1.4.1.188.7.1.1.2",
        "IDEA-CBC",
    );

    /// CAST5 in CBC mode.
    pub const CAST5_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 0x07, 0x42, 0x0a],
        "1.2.840.113533.7.66.10",
        "cast5CBC",
    );

    /// DES in CBC mode.
    pub const DES_CBC: NamedOid =
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x07], "1.3.14.3.2.7", "desCBC");

    /// Triple DES in CBC mode.
    pub const DES_EDE3_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07],
        "1.2.840.113549.3.7",
        "des-ede3-cbc",
    );

    /// RC2 in CBC mode; the parameter is the key size.
    pub const RC2_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02],
        "1.2.840.113549.3.2",
        "rc2CBC",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::PREFER_SIGNED_DATA,
        Self::CANNOT_DECRYPT_ANY,
        Self::SMIME_CAPABILITIES_VERSIONS,
        Self::AES256_CBC,
        Self::AES192_CBC,
        Self::AES128_CBC,
        Self::IDEA_CBC,
        Self::CAST5_CBC,
        Self::DES_CBC,
        Self::DES_EDE3_CBC,
        Self::RC2_CBC,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
