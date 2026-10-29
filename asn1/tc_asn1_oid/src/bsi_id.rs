//! BSI (Germany) TR-03111 algorithm identifiers, as Bouncy Castle's
//! `BsiObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// BSI (Germany) TR-03111 algorithm identifiers.
///
/// ```
/// use tc_asn1_oid::BsiId;
///
/// assert_eq!(BsiId::ID_ECC.dotted(), "0.4.0.127.0.7.1.1");
/// assert_eq!(
///     BsiId::from_oid(&BsiId::ID_ECC.oid()),
///     Some(BsiId::ID_ECC),
/// );
/// ```
pub struct BsiId;

impl BsiId {
    /// Bouncy Castle's `bsi_de`.
    pub const BSI_DE: NamedOid =
        NamedOid::new(&[0x04, 0x00, 0x7f, 0x00, 0x07], "0.4.0.127.0.7", "bsi_de");

    /// Bouncy Castle's `id_ecc`.
    pub const ID_ECC: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01],
        "0.4.0.127.0.7.1.1",
        "id_ecc",
    );

    /// Bouncy Castle's `ecdsa_plain_signatures`.
    pub const ECDSA_PLAIN_SIGNATURES: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01],
        "0.4.0.127.0.7.1.1.4.1",
        "ecdsa_plain_signatures",
    );

    /// Bouncy Castle's `ecdsa_plain_SHA1`.
    pub const ECDSA_PLAIN_SHA1: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x01],
        "0.4.0.127.0.7.1.1.4.1.1",
        "ecdsa_plain_SHA1",
    );

    /// Bouncy Castle's `ecdsa_plain_SHA224`.
    pub const ECDSA_PLAIN_SHA224: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x02],
        "0.4.0.127.0.7.1.1.4.1.2",
        "ecdsa_plain_SHA224",
    );

    /// Bouncy Castle's `ecdsa_plain_SHA256`.
    pub const ECDSA_PLAIN_SHA256: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x03],
        "0.4.0.127.0.7.1.1.4.1.3",
        "ecdsa_plain_SHA256",
    );

    /// Bouncy Castle's `ecdsa_plain_SHA384`.
    pub const ECDSA_PLAIN_SHA384: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x04],
        "0.4.0.127.0.7.1.1.4.1.4",
        "ecdsa_plain_SHA384",
    );

    /// Bouncy Castle's `ecdsa_plain_SHA512`.
    pub const ECDSA_PLAIN_SHA512: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x05],
        "0.4.0.127.0.7.1.1.4.1.5",
        "ecdsa_plain_SHA512",
    );

    /// Bouncy Castle's `ecdsa_plain_RIPEMD160`.
    pub const ECDSA_PLAIN_RIPEMD160: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x06],
        "0.4.0.127.0.7.1.1.4.1.6",
        "ecdsa_plain_RIPEMD160",
    );

    /// Bouncy Castle's `ecdsa_plain_SHA3_224`.
    pub const ECDSA_PLAIN_SHA3_224: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x08],
        "0.4.0.127.0.7.1.1.4.1.8",
        "ecdsa_plain_SHA3_224",
    );

    /// Bouncy Castle's `ecdsa_plain_SHA3_256`.
    pub const ECDSA_PLAIN_SHA3_256: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x09],
        "0.4.0.127.0.7.1.1.4.1.9",
        "ecdsa_plain_SHA3_256",
    );

    /// Bouncy Castle's `ecdsa_plain_SHA3_384`.
    pub const ECDSA_PLAIN_SHA3_384: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x0a],
        "0.4.0.127.0.7.1.1.4.1.10",
        "ecdsa_plain_SHA3_384",
    );

    /// Bouncy Castle's `ecdsa_plain_SHA3_512`.
    pub const ECDSA_PLAIN_SHA3_512: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x0b],
        "0.4.0.127.0.7.1.1.4.1.11",
        "ecdsa_plain_SHA3_512",
    );

    /// Bouncy Castle's `algorithm`.
    pub const ALGORITHM: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01],
        "0.4.0.127.0.7.1",
        "algorithm",
    );

    /// Bouncy Castle's `ecka_eg`.
    pub const ECKA_EG: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01],
        "0.4.0.127.0.7.1.1.5.1",
        "ecka_eg",
    );

    /// Bouncy Castle's `ecka_eg_X963kdf`.
    pub const ECKA_EG_X963KDF: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01, 0x01],
        "0.4.0.127.0.7.1.1.5.1.1",
        "ecka_eg_X963kdf",
    );

    /// Bouncy Castle's `ecka_eg_X963kdf_SHA1`.
    pub const ECKA_EG_X963KDF_SHA1: NamedOid = NamedOid::new(
        &[
            0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01, 0x01, 0x01,
        ],
        "0.4.0.127.0.7.1.1.5.1.1.1",
        "ecka_eg_X963kdf_SHA1",
    );

    /// Bouncy Castle's `ecka_eg_X963kdf_SHA224`.
    pub const ECKA_EG_X963KDF_SHA224: NamedOid = NamedOid::new(
        &[
            0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01, 0x01, 0x02,
        ],
        "0.4.0.127.0.7.1.1.5.1.1.2",
        "ecka_eg_X963kdf_SHA224",
    );

    /// Bouncy Castle's `ecka_eg_X963kdf_SHA256`.
    pub const ECKA_EG_X963KDF_SHA256: NamedOid = NamedOid::new(
        &[
            0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01, 0x01, 0x03,
        ],
        "0.4.0.127.0.7.1.1.5.1.1.3",
        "ecka_eg_X963kdf_SHA256",
    );

    /// Bouncy Castle's `ecka_eg_X963kdf_SHA384`.
    pub const ECKA_EG_X963KDF_SHA384: NamedOid = NamedOid::new(
        &[
            0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01, 0x01, 0x04,
        ],
        "0.4.0.127.0.7.1.1.5.1.1.4",
        "ecka_eg_X963kdf_SHA384",
    );

    /// Bouncy Castle's `ecka_eg_X963kdf_SHA512`.
    pub const ECKA_EG_X963KDF_SHA512: NamedOid = NamedOid::new(
        &[
            0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01, 0x01, 0x05,
        ],
        "0.4.0.127.0.7.1.1.5.1.1.5",
        "ecka_eg_X963kdf_SHA512",
    );

    /// Bouncy Castle's `ecka_eg_X963kdf_RIPEMD160`.
    pub const ECKA_EG_X963KDF_RIPEMD160: NamedOid = NamedOid::new(
        &[
            0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01, 0x01, 0x06,
        ],
        "0.4.0.127.0.7.1.1.5.1.1.6",
        "ecka_eg_X963kdf_RIPEMD160",
    );

    /// Bouncy Castle's `ecka_eg_SessionKDF`.
    pub const ECKA_EG_SESSION_KDF: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01, 0x02],
        "0.4.0.127.0.7.1.1.5.1.2",
        "ecka_eg_SessionKDF",
    );

    /// Bouncy Castle's `ecka_eg_SessionKDF_3DES`.
    pub const ECKA_EG_SESSION_KDF_3DES: NamedOid = NamedOid::new(
        &[
            0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01, 0x02, 0x01,
        ],
        "0.4.0.127.0.7.1.1.5.1.2.1",
        "ecka_eg_SessionKDF_3DES",
    );

    /// Bouncy Castle's `ecka_eg_SessionKDF_AES128`.
    pub const ECKA_EG_SESSION_KDF_AES128: NamedOid = NamedOid::new(
        &[
            0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01, 0x02, 0x02,
        ],
        "0.4.0.127.0.7.1.1.5.1.2.2",
        "ecka_eg_SessionKDF_AES128",
    );

    /// Bouncy Castle's `ecka_eg_SessionKDF_AES192`.
    pub const ECKA_EG_SESSION_KDF_AES192: NamedOid = NamedOid::new(
        &[
            0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01, 0x02, 0x03,
        ],
        "0.4.0.127.0.7.1.1.5.1.2.3",
        "ecka_eg_SessionKDF_AES192",
    );

    /// Bouncy Castle's `ecka_eg_SessionKDF_AES256`.
    pub const ECKA_EG_SESSION_KDF_AES256: NamedOid = NamedOid::new(
        &[
            0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x05, 0x01, 0x02, 0x04,
        ],
        "0.4.0.127.0.7.1.1.5.1.2.4",
        "ecka_eg_SessionKDF_AES256",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::BSI_DE,
        Self::ID_ECC,
        Self::ECDSA_PLAIN_SIGNATURES,
        Self::ECDSA_PLAIN_SHA1,
        Self::ECDSA_PLAIN_SHA224,
        Self::ECDSA_PLAIN_SHA256,
        Self::ECDSA_PLAIN_SHA384,
        Self::ECDSA_PLAIN_SHA512,
        Self::ECDSA_PLAIN_RIPEMD160,
        Self::ECDSA_PLAIN_SHA3_224,
        Self::ECDSA_PLAIN_SHA3_256,
        Self::ECDSA_PLAIN_SHA3_384,
        Self::ECDSA_PLAIN_SHA3_512,
        Self::ALGORITHM,
        Self::ECKA_EG,
        Self::ECKA_EG_X963KDF,
        Self::ECKA_EG_X963KDF_SHA1,
        Self::ECKA_EG_X963KDF_SHA224,
        Self::ECKA_EG_X963KDF_SHA256,
        Self::ECKA_EG_X963KDF_SHA384,
        Self::ECKA_EG_X963KDF_SHA512,
        Self::ECKA_EG_X963KDF_RIPEMD160,
        Self::ECKA_EG_SESSION_KDF,
        Self::ECKA_EG_SESSION_KDF_3DES,
        Self::ECKA_EG_SESSION_KDF_AES128,
        Self::ECKA_EG_SESSION_KDF_AES192,
        Self::ECKA_EG_SESSION_KDF_AES256,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
