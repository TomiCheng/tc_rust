//! CRMF identifiers, as Bouncy Castle's `CrmfObjectIdentifiers` names them:
//! registration controls and information, and proof-of-possession algorithms.
//!
//! This table names known identifiers without restricting which are used.

use tc_asn1::{Asn1Oid, NamedOid};

/// RFC 4211 controls, registration information and algorithms.
///
/// ```
/// use tc_asn1_cmp::crmf::CrmfId;
///
/// assert_eq!(CrmfId::REG_TOKEN.dotted(), "1.3.6.1.5.5.7.5.1.1");
/// assert_eq!(
///     CrmfId::from_oid(&CrmfId::PASSWORD_BASED_MAC.oid()),
///     Some(CrmfId::PASSWORD_BASED_MAC),
/// );
/// ```
pub struct CrmfId;

impl CrmfId {
    /// The password-based MAC of a `PKMACValue`.
    pub const PASSWORD_BASED_MAC: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 0x07, 0x42, 0x0d],
        "1.2.840.113533.7.66.13",
        "passwordBasedMac",
    );

    /// The CRMF arc.
    pub const ID_PKIP: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05],
        "1.3.6.1.5.5.7.5",
        "id-pkip",
    );

    /// The arc of registration controls.
    pub const REG_CTRL: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x01],
        "1.3.6.1.5.5.7.5.1",
        "id-regCtrl",
    );

    /// A one-time secret from the CA.
    pub const REG_TOKEN: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x01, 0x01],
        "1.3.6.1.5.5.7.5.1.1",
        "id-regCtrl-regToken",
    );

    /// A long-term secret for later requests.
    pub const AUTHENTICATOR: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x01, 0x02],
        "1.3.6.1.5.5.7.5.1.2",
        "id-regCtrl-authenticator",
    );

    /// A `PkiPublicationInfo`.
    pub const PKI_PUBLICATION_INFO: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x01, 0x03],
        "1.3.6.1.5.5.7.5.1.3",
        "id-regCtrl-pkiPublicationInfo",
    );

    /// A `PkiArchiveOptions`.
    pub const PKI_ARCHIVE_OPTIONS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x01, 0x04],
        "1.3.6.1.5.5.7.5.1.4",
        "id-regCtrl-pkiArchiveOptions",
    );

    /// The `CertId` of the certificate to update.
    pub const OLD_CERT_ID: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x01, 0x05],
        "1.3.6.1.5.5.7.5.1.5",
        "id-regCtrl-oldCertID",
    );

    /// A key to encrypt responses with.
    pub const PROTOCOL_ENCR_KEY: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x01, 0x06],
        "1.3.6.1.5.5.7.5.1.6",
        "id-regCtrl-protocolEncrKey",
    );

    /// The arc of registration information.
    pub const REG_INFO: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x02],
        "1.3.6.1.5.5.7.5.2",
        "id-regInfo",
    );

    /// Name-value pairs as text.
    pub const UTF8_PAIRS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x02, 0x01],
        "1.3.6.1.5.5.7.5.2.1",
        "id-regInfo-utf8Pairs",
    );

    /// A `CertRequest`.
    pub const CERT_REQ: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x02, 0x02],
        "1.3.6.1.5.5.7.5.2.2",
        "id-regInfo-certReq",
    );

    /// The content type of an `EncKeyWithId`.
    pub const ENC_KEY_WITH_ID: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x15,
        ],
        "1.2.840.113549.1.9.16.1.21",
        "id-ct-encKeyWithID",
    );

    /// The Diffie-Hellman POP of RFC 2875.
    pub const DH_SIG_HMAC_SHA1: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x03],
        "1.3.6.1.5.5.7.6.3",
        "id-dh-sig-hmac-sha1",
    );

    /// The static Diffie-Hellman POP of RFC 2875.
    pub const ALG_DH_POP: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x04],
        "1.3.6.1.5.5.7.6.4",
        "id-alg-dh-pop",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::PASSWORD_BASED_MAC,
        Self::ID_PKIP,
        Self::REG_CTRL,
        Self::REG_TOKEN,
        Self::AUTHENTICATOR,
        Self::PKI_PUBLICATION_INFO,
        Self::PKI_ARCHIVE_OPTIONS,
        Self::OLD_CERT_ID,
        Self::PROTOCOL_ENCR_KEY,
        Self::REG_INFO,
        Self::UTF8_PAIRS,
        Self::CERT_REQ,
        Self::ENC_KEY_WITH_ID,
        Self::DH_SIG_HMAC_SHA1,
        Self::ALG_DH_POP,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
