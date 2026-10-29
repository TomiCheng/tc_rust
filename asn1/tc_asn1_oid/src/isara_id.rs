//! ISARA post-quantum algorithm identifiers, as Bouncy Castle's
//! `IsaraObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// ISARA post-quantum algorithm identifiers.
///
/// ```
/// use tc_asn1_oid::IsaraId;
///
/// assert_eq!(IsaraId::ID_ALG_XMSSMT.dotted(), "0.4.0.127.0.15.1.1.14.0");
/// assert_eq!(
///     IsaraId::from_oid(&IsaraId::ID_ALG_XMSSMT.oid()),
///     Some(IsaraId::ID_ALG_XMSSMT),
/// );
/// ```
pub struct IsaraId;

impl IsaraId {
    /// Bouncy Castle's `id_alg_xmss`.
    pub const ID_ALG_XMSS: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x0f, 0x01, 0x01, 0x0d, 0x00],
        "0.4.0.127.0.15.1.1.13.0",
        "id_alg_xmss",
    );

    /// Bouncy Castle's `id_alg_xmssmt`.
    pub const ID_ALG_XMSSMT: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x0f, 0x01, 0x01, 0x0e, 0x00],
        "0.4.0.127.0.15.1.1.14.0",
        "id_alg_xmssmt",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[Self::ID_ALG_XMSS, Self::ID_ALG_XMSSMT];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
