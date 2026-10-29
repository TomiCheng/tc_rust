//! ANSSI (France) curve identifiers, as Bouncy Castle's
//! `AnssiObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// ANSSI (France) curve identifiers.
///
/// ```
/// use tc_asn1_oid::AnssiId;
///
/// assert_eq!(AnssiId::FRP256V1.dotted(), "1.2.250.1.223.101.256.1");
/// assert_eq!(
///     AnssiId::from_oid(&AnssiId::FRP256V1.oid()),
///     Some(AnssiId::FRP256V1),
/// );
/// ```
pub struct AnssiId;

impl AnssiId {
    /// Bouncy Castle's `FRP256v1`.
    pub const FRP256V1: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x7a, 0x01, 0x81, 0x5f, 0x65, 0x82, 0x00, 0x01],
        "1.2.250.1.223.101.256.1",
        "FRP256v1",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[Self::FRP256V1];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
