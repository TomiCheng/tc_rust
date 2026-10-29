//! NTT (Japan) Camellia identifiers, as Bouncy Castle's `NttObjectIdentifiers`
//! names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// NTT (Japan) Camellia identifiers.
///
/// ```
/// use tc_asn1_oid::NttId;
///
/// assert_eq!(NttId::ID_CAMELLIA192_CBC.dotted(), "1.2.392.200011.61.1.1.1.3");
/// assert_eq!(
///     NttId::from_oid(&NttId::ID_CAMELLIA192_CBC.oid()),
///     Some(NttId::ID_CAMELLIA192_CBC),
/// );
/// ```
pub struct NttId;

impl NttId {
    /// Bouncy Castle's `IdCamellia128Cbc`.
    pub const ID_CAMELLIA128_CBC: NamedOid = NamedOid::new(
        &[
            0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x01, 0x02,
        ],
        "1.2.392.200011.61.1.1.1.2",
        "IdCamellia128Cbc",
    );

    /// Bouncy Castle's `IdCamellia192Cbc`.
    pub const ID_CAMELLIA192_CBC: NamedOid = NamedOid::new(
        &[
            0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x01, 0x03,
        ],
        "1.2.392.200011.61.1.1.1.3",
        "IdCamellia192Cbc",
    );

    /// Bouncy Castle's `IdCamellia256Cbc`.
    pub const ID_CAMELLIA256_CBC: NamedOid = NamedOid::new(
        &[
            0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x01, 0x04,
        ],
        "1.2.392.200011.61.1.1.1.4",
        "IdCamellia256Cbc",
    );

    /// Bouncy Castle's `IdCamellia128Wrap`.
    pub const ID_CAMELLIA128_WRAP: NamedOid = NamedOid::new(
        &[
            0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x03, 0x02,
        ],
        "1.2.392.200011.61.1.1.3.2",
        "IdCamellia128Wrap",
    );

    /// Bouncy Castle's `IdCamellia192Wrap`.
    pub const ID_CAMELLIA192_WRAP: NamedOid = NamedOid::new(
        &[
            0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x03, 0x03,
        ],
        "1.2.392.200011.61.1.1.3.3",
        "IdCamellia192Wrap",
    );

    /// Bouncy Castle's `IdCamellia256Wrap`.
    pub const ID_CAMELLIA256_WRAP: NamedOid = NamedOid::new(
        &[
            0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x03, 0x04,
        ],
        "1.2.392.200011.61.1.1.3.4",
        "IdCamellia256Wrap",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::ID_CAMELLIA128_CBC,
        Self::ID_CAMELLIA192_CBC,
        Self::ID_CAMELLIA256_CBC,
        Self::ID_CAMELLIA128_WRAP,
        Self::ID_CAMELLIA192_WRAP,
        Self::ID_CAMELLIA256_WRAP,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
