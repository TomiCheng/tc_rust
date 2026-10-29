//! CMP identifiers, as Bouncy Castle's `CmpObjectIdentifiers` names them:
//! protection algorithms and `id-it` information types. The registration
//! controls it repeats are in `crmf::CrmfId`.
//!
//! This table names known identifiers without restricting which are used.

use tc_asn1::{Asn1Oid, NamedOid};

/// RFC 4210, RFC 9480 and RFC 9810 identifiers.
///
/// ```
/// use tc_asn1_cmp::CmpId;
///
/// assert_eq!(CmpId::IMPLICIT_CONFIRM.dotted(), "1.3.6.1.5.5.7.4.13");
/// assert_eq!(
///     CmpId::from_oid(&CmpId::KEM_BASED_MAC.oid()),
///     Some(CmpId::KEM_BASED_MAC),
/// );
/// ```
pub struct CmpId;

impl CmpId {
    /// MAC protection under a KEM shared secret.
    pub const KEM_BASED_MAC: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 0x07, 0x42, 0x10],
        "1.2.840.113533.7.66.16",
        "id-KemBasedMac",
    );

    /// MAC protection under a Diffie-Hellman shared secret.
    pub const DH_BASED_MAC: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 0x07, 0x42, 0x1e],
        "1.2.840.113533.7.66.30",
        "id-DHBasedMac",
    );

    /// The arc of information types.
    pub const ID_IT: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04],
        "1.3.6.1.5.5.7.4",
        "id-it",
    );

    /// A CA certificate for protecting messages.
    pub const CA_PROT_ENC_CERT: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x01],
        "1.3.6.1.5.5.7.4.1",
        "id-it-caProtEncCert",
    );

    /// Signature key types the CA supports.
    pub const SIGN_KEY_PAIR_TYPES: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x02],
        "1.3.6.1.5.5.7.4.2",
        "id-it-signKeyPairTypes",
    );

    /// Encryption key types the CA supports.
    pub const ENC_KEY_PAIR_TYPES: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x03],
        "1.3.6.1.5.5.7.4.3",
        "id-it-encKeyPairTypes",
    );

    /// The preferred symmetric algorithm.
    pub const PREFERRED_SYMM_ALG: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x04],
        "1.3.6.1.5.5.7.4.4",
        "id-it-preferredSymmAlg",
    );

    /// A `CaKeyUpdAnnContent`.
    pub const CA_KEY_UPDATE_INFO: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x05],
        "1.3.6.1.5.5.7.4.5",
        "id-it-caKeyUpdateInfo",
    );

    /// The current CRL.
    pub const CURRENT_CRL: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x06],
        "1.3.6.1.5.5.7.4.6",
        "id-it-currentCRL",
    );

    /// Information types not understood.
    pub const UNSUPPORTED_OIDS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x07],
        "1.3.6.1.5.5.7.4.7",
        "id-it-unsupportedOIDs",
    );

    /// A request for key parameters.
    pub const KEY_PAIR_PARAM_REQ: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x0a],
        "1.3.6.1.5.5.7.4.10",
        "id-it-keyPairParamReq",
    );

    /// The key parameters asked for.
    pub const KEY_PAIR_PARAM_REP: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x0b],
        "1.3.6.1.5.5.7.4.11",
        "id-it-keyPairParamRep",
    );

    /// A passphrase to authorize revocation.
    pub const REV_PASSPHRASE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x0c],
        "1.3.6.1.5.5.7.4.12",
        "id-it-revPassphrase",
    );

    /// Skip the certificate confirmation.
    pub const IMPLICIT_CONFIRM: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x0d],
        "1.3.6.1.5.5.7.4.13",
        "id-it-implicitConfirm",
    );

    /// How long the CA waits for a confirmation.
    pub const CONFIRM_WAIT_TIME: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x0e],
        "1.3.6.1.5.5.7.4.14",
        "id-it-confirmWaitTime",
    );

    /// The original message, as `PkiMessages`.
    pub const ORIG_PKI_MESSAGE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x0f],
        "1.3.6.1.5.5.7.4.15",
        "id-it-origPKIMessage",
    );

    /// The languages for free text.
    pub const SUPP_LANG_TAGS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x10],
        "1.3.6.1.5.5.7.4.16",
        "id-it-suppLangTags",
    );

    /// CA certificates.
    pub const CA_CERTS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x11],
        "1.3.6.1.5.5.7.4.17",
        "id-it-caCerts",
    );

    /// A `RootCaKeyUpdateContent`.
    pub const ROOT_CA_KEY_UPDATE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x12],
        "1.3.6.1.5.5.7.4.18",
        "id-it-rootCaKeyUpdate",
    );

    /// A `CertReqTemplateContent`.
    pub const CERT_REQ_TEMPLATE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x13],
        "1.3.6.1.5.5.7.4.19",
        "id-it-certReqTemplate",
    );

    /// The root CA certificate to update.
    pub const ROOT_CA_CERT: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x14],
        "1.3.6.1.5.5.7.4.20",
        "id-it-rootCaCert",
    );

    /// Certificate profile names.
    pub const CERT_PROFILE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x15],
        "1.3.6.1.5.5.7.4.21",
        "id-it-certProfile",
    );

    /// The `CrlStatus` of CRLs held.
    pub const CRL_STATUS_LIST: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x16],
        "1.3.6.1.5.5.7.4.22",
        "id-it-crlStatusList",
    );

    /// CRLs.
    pub const CRLS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x17],
        "1.3.6.1.5.5.7.4.23",
        "id-it-crls",
    );

    /// A template for a non-X.509 certificate.
    pub const REG_CTRL_ALT_CERT_TEMPLATE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x01, 0x07],
        "1.3.6.1.5.5.7.5.1.7",
        "id-regCtrl-altCertTemplate",
    );

    /// The algorithm of the key to generate.
    pub const REG_CTRL_ALG_ID: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x01, 0x0b],
        "1.3.6.1.5.5.7.5.1.11",
        "id-regCtrl-algId",
    );

    /// The length of the RSA key to generate.
    pub const REG_CTRL_RSA_KEY_LEN: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x01, 0x0c],
        "1.3.6.1.5.5.7.5.1.12",
        "id-regCtrl-rsaKeyLen",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::KEM_BASED_MAC,
        Self::DH_BASED_MAC,
        Self::ID_IT,
        Self::CA_PROT_ENC_CERT,
        Self::SIGN_KEY_PAIR_TYPES,
        Self::ENC_KEY_PAIR_TYPES,
        Self::PREFERRED_SYMM_ALG,
        Self::CA_KEY_UPDATE_INFO,
        Self::CURRENT_CRL,
        Self::UNSUPPORTED_OIDS,
        Self::KEY_PAIR_PARAM_REQ,
        Self::KEY_PAIR_PARAM_REP,
        Self::REV_PASSPHRASE,
        Self::IMPLICIT_CONFIRM,
        Self::CONFIRM_WAIT_TIME,
        Self::ORIG_PKI_MESSAGE,
        Self::SUPP_LANG_TAGS,
        Self::CA_CERTS,
        Self::ROOT_CA_KEY_UPDATE,
        Self::CERT_REQ_TEMPLATE,
        Self::ROOT_CA_CERT,
        Self::CERT_PROFILE,
        Self::CRL_STATUS_LIST,
        Self::CRLS,
        Self::REG_CTRL_ALT_CERT_TEMPLATE,
        Self::REG_CTRL_ALG_ID,
        Self::REG_CTRL_RSA_KEY_LEN,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
