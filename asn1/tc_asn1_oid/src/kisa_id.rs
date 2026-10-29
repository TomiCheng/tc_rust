//! KISA (Korea) SEED identifiers, as Bouncy Castle's `KisaObjectIdentifiers`
//! names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// KISA (Korea) SEED identifiers.
///
/// ```
/// use tc_asn1_oid::KisaId;
///
/// assert_eq!(KisaId::ID_NPKI_APP_CMS_SEED_WRAP.dotted(), "1.2.410.200004.7.1.1.1");
/// assert_eq!(
///     KisaId::from_oid(&KisaId::ID_NPKI_APP_CMS_SEED_WRAP.oid()),
///     Some(KisaId::ID_NPKI_APP_CMS_SEED_WRAP),
/// );
/// ```
pub struct KisaId;

impl KisaId {
    /// Bouncy Castle's `IdSeedCbc`.
    pub const ID_SEED_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x44, 0x01, 0x04],
        "1.2.410.200004.1.4",
        "IdSeedCbc",
    );

    /// Bouncy Castle's `IdNpkiAppCmsSeedWrap`.
    pub const ID_NPKI_APP_CMS_SEED_WRAP: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x44, 0x07, 0x01, 0x01, 0x01],
        "1.2.410.200004.7.1.1.1",
        "IdNpkiAppCmsSeedWrap",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[Self::ID_SEED_CBC, Self::ID_NPKI_APP_CMS_SEED_WRAP];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
