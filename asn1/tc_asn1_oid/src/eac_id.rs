//! BSI TR-03110 extended access control identifiers, as Bouncy Castle's
//! `EacObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// BSI TR-03110 extended access control identifiers.
///
/// ```
/// use tc_asn1_oid::EacId;
///
/// assert_eq!(EacId::ID_PK.dotted(), "0.4.0.127.0.7.2.2.1");
/// assert_eq!(
///     EacId::from_oid(&EacId::ID_PK.oid()),
///     Some(EacId::ID_PK),
/// );
/// ```
pub struct EacId;

impl EacId {
    /// Bouncy Castle's `bsi_de`.
    pub const BSI_DE: NamedOid =
        NamedOid::new(&[0x04, 0x00, 0x7f, 0x00, 0x07], "0.4.0.127.0.7", "bsi_de");

    /// Bouncy Castle's `id_PK`.
    pub const ID_PK: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x01],
        "0.4.0.127.0.7.2.2.1",
        "id_PK",
    );

    /// Bouncy Castle's `id_PK_DH`.
    pub const ID_PK_DH: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x01, 0x01],
        "0.4.0.127.0.7.2.2.1.1",
        "id_PK_DH",
    );

    /// Bouncy Castle's `id_PK_ECDH`.
    pub const ID_PK_ECDH: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x01, 0x02],
        "0.4.0.127.0.7.2.2.1.2",
        "id_PK_ECDH",
    );

    /// Bouncy Castle's `id_CA`.
    pub const ID_CA: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x03],
        "0.4.0.127.0.7.2.2.3",
        "id_CA",
    );

    /// Bouncy Castle's `id_CA_DH`.
    pub const ID_CA_DH: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01],
        "0.4.0.127.0.7.2.2.3.1",
        "id_CA_DH",
    );

    /// Bouncy Castle's `id_CA_DH_3DES_CBC_CBC`.
    pub const ID_CA_DH_3DES_CBC_CBC: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x01],
        "0.4.0.127.0.7.2.2.3.1.1",
        "id_CA_DH_3DES_CBC_CBC",
    );

    /// Bouncy Castle's `id_CA_ECDH`.
    pub const ID_CA_ECDH: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02],
        "0.4.0.127.0.7.2.2.3.2",
        "id_CA_ECDH",
    );

    /// Bouncy Castle's `id_CA_ECDH_3DES_CBC_CBC`.
    pub const ID_CA_ECDH_3DES_CBC_CBC: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x01],
        "0.4.0.127.0.7.2.2.3.2.1",
        "id_CA_ECDH_3DES_CBC_CBC",
    );

    /// Bouncy Castle's `id_TA`.
    pub const ID_TA: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02],
        "0.4.0.127.0.7.2.2.2",
        "id_TA",
    );

    /// Bouncy Castle's `id_TA_RSA`.
    pub const ID_TA_RSA: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01],
        "0.4.0.127.0.7.2.2.2.1",
        "id_TA_RSA",
    );

    /// Bouncy Castle's `id_TA_RSA_v1_5_SHA_1`.
    pub const ID_TA_RSA_V1_5_SHA_1: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x01],
        "0.4.0.127.0.7.2.2.2.1.1",
        "id_TA_RSA_v1_5_SHA_1",
    );

    /// Bouncy Castle's `id_TA_RSA_v1_5_SHA_256`.
    pub const ID_TA_RSA_V1_5_SHA_256: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02],
        "0.4.0.127.0.7.2.2.2.1.2",
        "id_TA_RSA_v1_5_SHA_256",
    );

    /// Bouncy Castle's `id_TA_RSA_PSS_SHA_1`.
    pub const ID_TA_RSA_PSS_SHA_1: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x03],
        "0.4.0.127.0.7.2.2.2.1.3",
        "id_TA_RSA_PSS_SHA_1",
    );

    /// Bouncy Castle's `id_TA_RSA_PSS_SHA_256`.
    pub const ID_TA_RSA_PSS_SHA_256: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x04],
        "0.4.0.127.0.7.2.2.2.1.4",
        "id_TA_RSA_PSS_SHA_256",
    );

    /// Bouncy Castle's `id_TA_ECDSA`.
    pub const ID_TA_ECDSA: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02],
        "0.4.0.127.0.7.2.2.2.2",
        "id_TA_ECDSA",
    );

    /// Bouncy Castle's `id_TA_ECDSA_SHA_1`.
    pub const ID_TA_ECDSA_SHA_1: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x01],
        "0.4.0.127.0.7.2.2.2.2.1",
        "id_TA_ECDSA_SHA_1",
    );

    /// Bouncy Castle's `id_TA_ECDSA_SHA_224`.
    pub const ID_TA_ECDSA_SHA_224: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x02],
        "0.4.0.127.0.7.2.2.2.2.2",
        "id_TA_ECDSA_SHA_224",
    );

    /// Bouncy Castle's `id_TA_ECDSA_SHA_256`.
    pub const ID_TA_ECDSA_SHA_256: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03],
        "0.4.0.127.0.7.2.2.2.2.3",
        "id_TA_ECDSA_SHA_256",
    );

    /// Bouncy Castle's `id_TA_ECDSA_SHA_384`.
    pub const ID_TA_ECDSA_SHA_384: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x04],
        "0.4.0.127.0.7.2.2.2.2.4",
        "id_TA_ECDSA_SHA_384",
    );

    /// Bouncy Castle's `id_TA_ECDSA_SHA_512`.
    pub const ID_TA_ECDSA_SHA_512: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x05],
        "0.4.0.127.0.7.2.2.2.2.5",
        "id_TA_ECDSA_SHA_512",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::BSI_DE,
        Self::ID_PK,
        Self::ID_PK_DH,
        Self::ID_PK_ECDH,
        Self::ID_CA,
        Self::ID_CA_DH,
        Self::ID_CA_DH_3DES_CBC_CBC,
        Self::ID_CA_ECDH,
        Self::ID_CA_ECDH_3DES_CBC_CBC,
        Self::ID_TA,
        Self::ID_TA_RSA,
        Self::ID_TA_RSA_V1_5_SHA_1,
        Self::ID_TA_RSA_V1_5_SHA_256,
        Self::ID_TA_RSA_PSS_SHA_1,
        Self::ID_TA_RSA_PSS_SHA_256,
        Self::ID_TA_ECDSA,
        Self::ID_TA_ECDSA_SHA_1,
        Self::ID_TA_ECDSA_SHA_224,
        Self::ID_TA_ECDSA_SHA_256,
        Self::ID_TA_ECDSA_SHA_384,
        Self::ID_TA_ECDSA_SHA_512,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
