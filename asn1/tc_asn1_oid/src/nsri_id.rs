//! NSRI (Korea) ARIA identifiers, as Bouncy Castle's `NsriObjectIdentifiers`
//! names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.
//!
//! These names repeat an earlier identifier, so `ALL` and `from_oid` give the
//! first name instead:
//! - `ID_PAD_1`

use tc_asn1::{Asn1Oid, NamedOid};

/// NSRI (Korea) ARIA identifiers.
///
/// ```
/// use tc_asn1_oid::NsriId;
///
/// assert_eq!(NsriId::ID_ALGORITHM.dotted(), "1.2.410.200046.1");
/// assert_eq!(
///     NsriId::from_oid(&NsriId::ID_ALGORITHM.oid()),
///     Some(NsriId::ID_ALGORITHM),
/// );
/// ```
pub struct NsriId;

impl NsriId {
    /// Bouncy Castle's `nsri`.
    pub const NSRI: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e],
        "1.2.410.200046",
        "nsri",
    );

    /// Bouncy Castle's `id_algorithm`.
    pub const ID_ALGORITHM: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01],
        "1.2.410.200046.1",
        "id_algorithm",
    );

    /// Bouncy Castle's `id_sea`.
    pub const ID_SEA: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01],
        "1.2.410.200046.1.1",
        "id_sea",
    );

    /// Bouncy Castle's `id_pad`.
    pub const ID_PAD: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x02],
        "1.2.410.200046.1.2",
        "id_pad",
    );

    /// Bouncy Castle's `id_pad_null`.
    pub const ID_PAD_NULL: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x00],
        "1.2.410.200046.1.0",
        "id_pad_null",
    );

    /// Bouncy Castle's `id_pad_1`, the same identifier as [`Self::ID_SEA`].
    pub const ID_PAD_1: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01],
        "1.2.410.200046.1.1",
        "id_pad_1",
    );

    /// Bouncy Castle's `id_aria128_ecb`.
    pub const ID_ARIA128_ECB: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x01],
        "1.2.410.200046.1.1.1",
        "id_aria128_ecb",
    );

    /// Bouncy Castle's `id_aria128_cbc`.
    pub const ID_ARIA128_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x02],
        "1.2.410.200046.1.1.2",
        "id_aria128_cbc",
    );

    /// Bouncy Castle's `id_aria128_cfb`.
    pub const ID_ARIA128_CFB: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x03],
        "1.2.410.200046.1.1.3",
        "id_aria128_cfb",
    );

    /// Bouncy Castle's `id_aria128_ofb`.
    pub const ID_ARIA128_OFB: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x04],
        "1.2.410.200046.1.1.4",
        "id_aria128_ofb",
    );

    /// Bouncy Castle's `id_aria128_ctr`.
    pub const ID_ARIA128_CTR: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x05],
        "1.2.410.200046.1.1.5",
        "id_aria128_ctr",
    );

    /// Bouncy Castle's `id_aria192_ecb`.
    pub const ID_ARIA192_ECB: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x06],
        "1.2.410.200046.1.1.6",
        "id_aria192_ecb",
    );

    /// Bouncy Castle's `id_aria192_cbc`.
    pub const ID_ARIA192_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x07],
        "1.2.410.200046.1.1.7",
        "id_aria192_cbc",
    );

    /// Bouncy Castle's `id_aria192_cfb`.
    pub const ID_ARIA192_CFB: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x08],
        "1.2.410.200046.1.1.8",
        "id_aria192_cfb",
    );

    /// Bouncy Castle's `id_aria192_ofb`.
    pub const ID_ARIA192_OFB: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x09],
        "1.2.410.200046.1.1.9",
        "id_aria192_ofb",
    );

    /// Bouncy Castle's `id_aria192_ctr`.
    pub const ID_ARIA192_CTR: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x0a],
        "1.2.410.200046.1.1.10",
        "id_aria192_ctr",
    );

    /// Bouncy Castle's `id_aria256_ecb`.
    pub const ID_ARIA256_ECB: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x0b],
        "1.2.410.200046.1.1.11",
        "id_aria256_ecb",
    );

    /// Bouncy Castle's `id_aria256_cbc`.
    pub const ID_ARIA256_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x0c],
        "1.2.410.200046.1.1.12",
        "id_aria256_cbc",
    );

    /// Bouncy Castle's `id_aria256_cfb`.
    pub const ID_ARIA256_CFB: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x0d],
        "1.2.410.200046.1.1.13",
        "id_aria256_cfb",
    );

    /// Bouncy Castle's `id_aria256_ofb`.
    pub const ID_ARIA256_OFB: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x0e],
        "1.2.410.200046.1.1.14",
        "id_aria256_ofb",
    );

    /// Bouncy Castle's `id_aria256_ctr`.
    pub const ID_ARIA256_CTR: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x0f],
        "1.2.410.200046.1.1.15",
        "id_aria256_ctr",
    );

    /// Bouncy Castle's `id_aria128_cmac`.
    pub const ID_ARIA128_CMAC: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x15],
        "1.2.410.200046.1.1.21",
        "id_aria128_cmac",
    );

    /// Bouncy Castle's `id_aria192_cmac`.
    pub const ID_ARIA192_CMAC: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x16],
        "1.2.410.200046.1.1.22",
        "id_aria192_cmac",
    );

    /// Bouncy Castle's `id_aria256_cmac`.
    pub const ID_ARIA256_CMAC: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x17],
        "1.2.410.200046.1.1.23",
        "id_aria256_cmac",
    );

    /// Bouncy Castle's `id_aria128_ocb2`.
    pub const ID_ARIA128_OCB2: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x1f],
        "1.2.410.200046.1.1.31",
        "id_aria128_ocb2",
    );

    /// Bouncy Castle's `id_aria192_ocb2`.
    pub const ID_ARIA192_OCB2: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x20],
        "1.2.410.200046.1.1.32",
        "id_aria192_ocb2",
    );

    /// Bouncy Castle's `id_aria256_ocb2`.
    pub const ID_ARIA256_OCB2: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x21],
        "1.2.410.200046.1.1.33",
        "id_aria256_ocb2",
    );

    /// Bouncy Castle's `id_aria128_gcm`.
    pub const ID_ARIA128_GCM: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x22],
        "1.2.410.200046.1.1.34",
        "id_aria128_gcm",
    );

    /// Bouncy Castle's `id_aria192_gcm`.
    pub const ID_ARIA192_GCM: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x23],
        "1.2.410.200046.1.1.35",
        "id_aria192_gcm",
    );

    /// Bouncy Castle's `id_aria256_gcm`.
    pub const ID_ARIA256_GCM: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x24],
        "1.2.410.200046.1.1.36",
        "id_aria256_gcm",
    );

    /// Bouncy Castle's `id_aria128_ccm`.
    pub const ID_ARIA128_CCM: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x25],
        "1.2.410.200046.1.1.37",
        "id_aria128_ccm",
    );

    /// Bouncy Castle's `id_aria192_ccm`.
    pub const ID_ARIA192_CCM: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x26],
        "1.2.410.200046.1.1.38",
        "id_aria192_ccm",
    );

    /// Bouncy Castle's `id_aria256_ccm`.
    pub const ID_ARIA256_CCM: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x27],
        "1.2.410.200046.1.1.39",
        "id_aria256_ccm",
    );

    /// Bouncy Castle's `id_aria128_kw`.
    pub const ID_ARIA128_KW: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x28],
        "1.2.410.200046.1.1.40",
        "id_aria128_kw",
    );

    /// Bouncy Castle's `id_aria192_kw`.
    pub const ID_ARIA192_KW: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x29],
        "1.2.410.200046.1.1.41",
        "id_aria192_kw",
    );

    /// Bouncy Castle's `id_aria256_kw`.
    pub const ID_ARIA256_KW: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x2a],
        "1.2.410.200046.1.1.42",
        "id_aria256_kw",
    );

    /// Bouncy Castle's `id_aria128_kwp`.
    pub const ID_ARIA128_KWP: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x2b],
        "1.2.410.200046.1.1.43",
        "id_aria128_kwp",
    );

    /// Bouncy Castle's `id_aria192_kwp`.
    pub const ID_ARIA192_KWP: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x2c],
        "1.2.410.200046.1.1.44",
        "id_aria192_kwp",
    );

    /// Bouncy Castle's `id_aria256_kwp`.
    pub const ID_ARIA256_KWP: NamedOid = NamedOid::new(
        &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, 0x2d],
        "1.2.410.200046.1.1.45",
        "id_aria256_kwp",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::NSRI,
        Self::ID_ALGORITHM,
        Self::ID_SEA,
        Self::ID_PAD,
        Self::ID_PAD_NULL,
        Self::ID_ARIA128_ECB,
        Self::ID_ARIA128_CBC,
        Self::ID_ARIA128_CFB,
        Self::ID_ARIA128_OFB,
        Self::ID_ARIA128_CTR,
        Self::ID_ARIA192_ECB,
        Self::ID_ARIA192_CBC,
        Self::ID_ARIA192_CFB,
        Self::ID_ARIA192_OFB,
        Self::ID_ARIA192_CTR,
        Self::ID_ARIA256_ECB,
        Self::ID_ARIA256_CBC,
        Self::ID_ARIA256_CFB,
        Self::ID_ARIA256_OFB,
        Self::ID_ARIA256_CTR,
        Self::ID_ARIA128_CMAC,
        Self::ID_ARIA192_CMAC,
        Self::ID_ARIA256_CMAC,
        Self::ID_ARIA128_OCB2,
        Self::ID_ARIA192_OCB2,
        Self::ID_ARIA256_OCB2,
        Self::ID_ARIA128_GCM,
        Self::ID_ARIA192_GCM,
        Self::ID_ARIA256_GCM,
        Self::ID_ARIA128_CCM,
        Self::ID_ARIA192_CCM,
        Self::ID_ARIA256_CCM,
        Self::ID_ARIA128_KW,
        Self::ID_ARIA192_KW,
        Self::ID_ARIA256_KW,
        Self::ID_ARIA128_KWP,
        Self::ID_ARIA192_KWP,
        Self::ID_ARIA256_KWP,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
