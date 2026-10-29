//! RFC 8410 Edwards and Montgomery curve identifiers, as Bouncy Castle's
//! `EdECObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// RFC 8410 Edwards and Montgomery curve identifiers.
///
/// ```
/// use tc_asn1_oid::EdecId;
///
/// assert_eq!(EdecId::ID_X25519.dotted(), "1.3.101.110");
/// assert_eq!(
///     EdecId::from_oid(&EdecId::ID_X25519.oid()),
///     Some(EdecId::ID_X25519),
/// );
/// ```
pub struct EdecId;

impl EdecId {
    /// Bouncy Castle's `id_edwards_curve_algs`.
    pub const ID_EDWARDS_CURVE_ALGS: NamedOid =
        NamedOid::new(&[0x2b, 0x65], "1.3.101", "id_edwards_curve_algs");

    /// Bouncy Castle's `id_X25519`.
    pub const ID_X25519: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x6e], "1.3.101.110", "id_X25519");

    /// Bouncy Castle's `id_X448`.
    pub const ID_X448: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x6f], "1.3.101.111", "id_X448");

    /// Bouncy Castle's `id_Ed25519`.
    pub const ID_ED25519: NamedOid =
        NamedOid::new(&[0x2b, 0x65, 0x70], "1.3.101.112", "id_Ed25519");

    /// Bouncy Castle's `id_Ed448`.
    pub const ID_ED448: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x71], "1.3.101.113", "id_Ed448");

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::ID_EDWARDS_CURVE_ALGS,
        Self::ID_X25519,
        Self::ID_X448,
        Self::ID_ED25519,
        Self::ID_ED448,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
