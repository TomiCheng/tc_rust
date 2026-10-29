//! cryptlib algorithm identifiers, as Bouncy Castle's
//! `CryptlibObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// cryptlib algorithm identifiers.
///
/// ```
/// use tc_asn1_oid::CryptlibId;
///
/// assert_eq!(CryptlibId::ECC.dotted(), "1.3.6.1.4.1.3029.1.5");
/// assert_eq!(
///     CryptlibId::from_oid(&CryptlibId::ECC.oid()),
///     Some(CryptlibId::ECC),
/// );
/// ```
pub struct CryptlibId;

impl CryptlibId {
    /// Bouncy Castle's `cryptlib`.
    pub const CRYPTLIB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55],
        "1.3.6.1.4.1.3029",
        "cryptlib",
    );

    /// Bouncy Castle's `ecc`.
    pub const ECC: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05],
        "1.3.6.1.4.1.3029.1.5",
        "ecc",
    );

    /// Bouncy Castle's `curvey25519`.
    pub const CURVEY25519: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01],
        "1.3.6.1.4.1.3029.1.5.1",
        "curvey25519",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[Self::CRYPTLIB, Self::ECC, Self::CURVEY25519];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
