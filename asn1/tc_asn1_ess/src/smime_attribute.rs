//! S/MIME attribute types, as Bouncy Castle's `SmimeAttributes` names them.

use tc_asn1::{Asn1Oid, NamedOid};

/// The S/MIME capabilities and encryption key preference attributes.
///
/// ```
/// use tc_asn1_ess::SmimeAttribute;
///
/// assert_eq!(SmimeAttribute::SMIME_CAPABILITIES.dotted(), "1.2.840.113549.1.9.15");
/// assert_eq!(
///     SmimeAttribute::from_oid(&SmimeAttribute::SMIME_CAPABILITIES.oid()),
///     Some(SmimeAttribute::SMIME_CAPABILITIES),
/// );
/// ```
pub struct SmimeAttribute;

impl SmimeAttribute {
    /// An `SmimeCapabilities`.
    pub const SMIME_CAPABILITIES: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0f],
        "1.2.840.113549.1.9.15",
        "smimeCapabilities",
    );

    /// An `SmimeEncryptionKeyPreference`.
    pub const ENCRYP_KEY_PREF: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0b,
        ],
        "1.2.840.113549.1.9.16.2.11",
        "id-aa-encrypKeyPref",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[Self::SMIME_CAPABILITIES, Self::ENCRYP_KEY_PREF];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
