//! Vendor identifiers (Netscape, VeriSign, Novell, Entrust, cryptlib, BLAKE2,
//! BLAKE3, scrypt and more), as Bouncy Castle's `MiscObjectIdentifiers` names
//! them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// Vendor identifiers (Netscape, VeriSign, Novell, Entrust, cryptlib, BLAKE2,
/// BLAKE3, scrypt and more).
///
/// ```
/// use tc_asn1_oid::MiscId;
///
/// assert_eq!(MiscId::NETSCAPE_CERT_TYPE.dotted(), "2.16.840.1.113730.1.1");
/// assert_eq!(
///     MiscId::from_oid(&MiscId::NETSCAPE_CERT_TYPE.oid()),
///     Some(MiscId::NETSCAPE_CERT_TYPE),
/// );
/// ```
pub struct MiscId;

impl MiscId {
    /// Bouncy Castle's `Netscape`.
    pub const NETSCAPE: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01],
        "2.16.840.1.113730.1",
        "Netscape",
    );

    /// Bouncy Castle's `NetscapeCertType`.
    pub const NETSCAPE_CERT_TYPE: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01],
        "2.16.840.1.113730.1.1",
        "NetscapeCertType",
    );

    /// Bouncy Castle's `NetscapeBaseUrl`.
    pub const NETSCAPE_BASE_URL: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x02],
        "2.16.840.1.113730.1.2",
        "NetscapeBaseUrl",
    );

    /// Bouncy Castle's `NetscapeRevocationUrl`.
    pub const NETSCAPE_REVOCATION_URL: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x03],
        "2.16.840.1.113730.1.3",
        "NetscapeRevocationUrl",
    );

    /// Bouncy Castle's `NetscapeCARevocationUrl`.
    pub const NETSCAPE_CA_REVOCATION_URL: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x04],
        "2.16.840.1.113730.1.4",
        "NetscapeCARevocationUrl",
    );

    /// Bouncy Castle's `NetscapeRenewalUrl`.
    pub const NETSCAPE_RENEWAL_URL: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x07],
        "2.16.840.1.113730.1.7",
        "NetscapeRenewalUrl",
    );

    /// Bouncy Castle's `NetscapeCAPolicyUrl`.
    pub const NETSCAPE_CA_POLICY_URL: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x08],
        "2.16.840.1.113730.1.8",
        "NetscapeCAPolicyUrl",
    );

    /// Bouncy Castle's `NetscapeSslServerName`.
    pub const NETSCAPE_SSL_SERVER_NAME: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x0c],
        "2.16.840.1.113730.1.12",
        "NetscapeSslServerName",
    );

    /// Bouncy Castle's `NetscapeCertComment`.
    pub const NETSCAPE_CERT_COMMENT: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x0d],
        "2.16.840.1.113730.1.13",
        "NetscapeCertComment",
    );

    /// Bouncy Castle's `Verisign`.
    pub const VERISIGN: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01],
        "2.16.840.1.113733.1",
        "Verisign",
    );

    /// Bouncy Castle's `VerisignCzagExtension`.
    pub const VERISIGN_CZAG_EXTENSION: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x06, 0x03],
        "2.16.840.1.113733.1.6.3",
        "VerisignCzagExtension",
    );

    /// Bouncy Castle's `VerisignPrivate_6_9`.
    pub const VERISIGN_PRIVATE_6_9: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x06, 0x09],
        "2.16.840.1.113733.1.6.9",
        "VerisignPrivate_6_9",
    );

    /// Bouncy Castle's `VerisignOnSiteJurisdictionHash`.
    pub const VERISIGN_ON_SITE_JURISDICTION_HASH: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x06, 0x0b],
        "2.16.840.1.113733.1.6.11",
        "VerisignOnSiteJurisdictionHash",
    );

    /// Bouncy Castle's `VerisignBitString_6_13`.
    pub const VERISIGN_BIT_STRING_6_13: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x06, 0x0d],
        "2.16.840.1.113733.1.6.13",
        "VerisignBitString_6_13",
    );

    /// Bouncy Castle's `VerisignDnbDunsNumber`.
    pub const VERISIGN_DNB_DUNS_NUMBER: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x06, 0x0f],
        "2.16.840.1.113733.1.6.15",
        "VerisignDnbDunsNumber",
    );

    /// Bouncy Castle's `VerisignIssStrongCrypto`.
    pub const VERISIGN_ISS_STRONG_CRYPTO: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x08, 0x01],
        "2.16.840.1.113733.1.8.1",
        "VerisignIssStrongCrypto",
    );

    /// Bouncy Castle's `Novell`.
    pub const NOVELL: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x37],
        "2.16.840.1.113719",
        "Novell",
    );

    /// Bouncy Castle's `NovellSecurityAttribs`.
    pub const NOVELL_SECURITY_ATTRIBS: NamedOid = NamedOid::new(
        &[
            0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x37, 0x01, 0x09, 0x04, 0x01,
        ],
        "2.16.840.1.113719.1.9.4.1",
        "NovellSecurityAttribs",
    );

    /// Bouncy Castle's `Entrust`.
    pub const ENTRUST: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 0x07],
        "1.2.840.113533.7",
        "Entrust",
    );

    /// Bouncy Castle's `EntrustVersionExtension`.
    pub const ENTRUST_VERSION_EXTENSION: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 0x07, 0x41, 0x00],
        "1.2.840.113533.7.65.0",
        "EntrustVersionExtension",
    );

    /// Bouncy Castle's `cast5CBC`.
    pub const CAST5CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 0x07, 0x42, 0x0a],
        "1.2.840.113533.7.66.10",
        "cast5CBC",
    );

    /// Bouncy Castle's `HMAC_SHA1`.
    pub const HMAC_SHA1: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x02],
        "1.3.6.1.5.5.8.1.2",
        "HMAC_SHA1",
    );

    /// Bouncy Castle's `as_sys_sec_alg_ideaCBC`.
    pub const AS_SYS_SEC_ALG_IDEA_CBC: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x3c, 0x07, 0x01, 0x01, 0x02,
        ],
        "1.3.6.1.4.1.188.7.1.1.2",
        "as_sys_sec_alg_ideaCBC",
    );

    /// Bouncy Castle's `cryptlib`.
    pub const CRYPTLIB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55],
        "1.3.6.1.4.1.3029",
        "cryptlib",
    );

    /// Bouncy Castle's `cryptlib_algorithm`.
    pub const CRYPTLIB_ALGORITHM: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01],
        "1.3.6.1.4.1.3029.1",
        "cryptlib_algorithm",
    );

    /// Bouncy Castle's `cryptlib_algorithm_blowfish_ECB`.
    pub const CRYPTLIB_ALGORITHM_BLOWFISH_ECB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x01, 0x01],
        "1.3.6.1.4.1.3029.1.1.1",
        "cryptlib_algorithm_blowfish_ECB",
    );

    /// Bouncy Castle's `cryptlib_algorithm_blowfish_CBC`.
    pub const CRYPTLIB_ALGORITHM_BLOWFISH_CBC: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x01, 0x02],
        "1.3.6.1.4.1.3029.1.1.2",
        "cryptlib_algorithm_blowfish_CBC",
    );

    /// Bouncy Castle's `cryptlib_algorithm_blowfish_CFB`.
    pub const CRYPTLIB_ALGORITHM_BLOWFISH_CFB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x01, 0x03],
        "1.3.6.1.4.1.3029.1.1.3",
        "cryptlib_algorithm_blowfish_CFB",
    );

    /// Bouncy Castle's `cryptlib_algorithm_blowfish_OFB`.
    pub const CRYPTLIB_ALGORITHM_BLOWFISH_OFB: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x01, 0x04],
        "1.3.6.1.4.1.3029.1.1.4",
        "cryptlib_algorithm_blowfish_OFB",
    );

    /// Bouncy Castle's `blake2`.
    pub const BLAKE2: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02],
        "1.3.6.1.4.1.1722.12.2",
        "blake2",
    );

    /// Bouncy Castle's `id_blake2b160`.
    pub const ID_BLAKE2B160: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x01, 0x05,
        ],
        "1.3.6.1.4.1.1722.12.2.1.5",
        "id_blake2b160",
    );

    /// Bouncy Castle's `id_blake2b256`.
    pub const ID_BLAKE2B256: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x01, 0x08,
        ],
        "1.3.6.1.4.1.1722.12.2.1.8",
        "id_blake2b256",
    );

    /// Bouncy Castle's `id_blake2b384`.
    pub const ID_BLAKE2B384: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x01, 0x0c,
        ],
        "1.3.6.1.4.1.1722.12.2.1.12",
        "id_blake2b384",
    );

    /// Bouncy Castle's `id_blake2b512`.
    pub const ID_BLAKE2B512: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x01, 0x10,
        ],
        "1.3.6.1.4.1.1722.12.2.1.16",
        "id_blake2b512",
    );

    /// Bouncy Castle's `id_blake2s128`.
    pub const ID_BLAKE2S128: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x02, 0x04,
        ],
        "1.3.6.1.4.1.1722.12.2.2.4",
        "id_blake2s128",
    );

    /// Bouncy Castle's `id_blake2s160`.
    pub const ID_BLAKE2S160: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x02, 0x05,
        ],
        "1.3.6.1.4.1.1722.12.2.2.5",
        "id_blake2s160",
    );

    /// Bouncy Castle's `id_blake2s224`.
    pub const ID_BLAKE2S224: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x02, 0x07,
        ],
        "1.3.6.1.4.1.1722.12.2.2.7",
        "id_blake2s224",
    );

    /// Bouncy Castle's `id_blake2s256`.
    pub const ID_BLAKE2S256: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x02, 0x08,
        ],
        "1.3.6.1.4.1.1722.12.2.2.8",
        "id_blake2s256",
    );

    /// Bouncy Castle's `blake3`.
    pub const BLAKE3: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x03],
        "1.3.6.1.4.1.1722.12.2.3",
        "blake3",
    );

    /// Bouncy Castle's `blake3_256`.
    pub const BLAKE3_256: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x03, 0x08,
        ],
        "1.3.6.1.4.1.1722.12.2.3.8",
        "blake3_256",
    );

    /// Bouncy Castle's `id_scrypt`.
    pub const ID_SCRYPT: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x04, 0x0b],
        "1.3.6.1.4.1.11591.4.11",
        "id_scrypt",
    );

    /// Bouncy Castle's `id_alg_composite`.
    pub const ID_ALG_COMPOSITE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x8e, 0x33, 0x02, 0x01],
        "1.3.6.1.4.1.18227.2.1",
        "id_alg_composite",
    );

    /// Bouncy Castle's `id_composite_key`.
    pub const ID_COMPOSITE_KEY: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xfa, 0x6b, 0x50, 0x04, 0x01],
        "2.16.840.1.114027.80.4.1",
        "id_composite_key",
    );

    /// Bouncy Castle's `id_oracle_pkcs12_trusted_key_usage`.
    pub const ID_ORACLE_PKCS12_TRUSTED_KEY_USAGE: NamedOid = NamedOid::new(
        &[
            0x60, 0x86, 0x48, 0x01, 0x86, 0xf9, 0x66, 0xad, 0xca, 0x7b, 0x01, 0x01,
        ],
        "2.16.840.1.113894.746875.1.1",
        "id_oracle_pkcs12_trusted_key_usage",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::NETSCAPE,
        Self::NETSCAPE_CERT_TYPE,
        Self::NETSCAPE_BASE_URL,
        Self::NETSCAPE_REVOCATION_URL,
        Self::NETSCAPE_CA_REVOCATION_URL,
        Self::NETSCAPE_RENEWAL_URL,
        Self::NETSCAPE_CA_POLICY_URL,
        Self::NETSCAPE_SSL_SERVER_NAME,
        Self::NETSCAPE_CERT_COMMENT,
        Self::VERISIGN,
        Self::VERISIGN_CZAG_EXTENSION,
        Self::VERISIGN_PRIVATE_6_9,
        Self::VERISIGN_ON_SITE_JURISDICTION_HASH,
        Self::VERISIGN_BIT_STRING_6_13,
        Self::VERISIGN_DNB_DUNS_NUMBER,
        Self::VERISIGN_ISS_STRONG_CRYPTO,
        Self::NOVELL,
        Self::NOVELL_SECURITY_ATTRIBS,
        Self::ENTRUST,
        Self::ENTRUST_VERSION_EXTENSION,
        Self::CAST5CBC,
        Self::HMAC_SHA1,
        Self::AS_SYS_SEC_ALG_IDEA_CBC,
        Self::CRYPTLIB,
        Self::CRYPTLIB_ALGORITHM,
        Self::CRYPTLIB_ALGORITHM_BLOWFISH_ECB,
        Self::CRYPTLIB_ALGORITHM_BLOWFISH_CBC,
        Self::CRYPTLIB_ALGORITHM_BLOWFISH_CFB,
        Self::CRYPTLIB_ALGORITHM_BLOWFISH_OFB,
        Self::BLAKE2,
        Self::ID_BLAKE2B160,
        Self::ID_BLAKE2B256,
        Self::ID_BLAKE2B384,
        Self::ID_BLAKE2B512,
        Self::ID_BLAKE2S128,
        Self::ID_BLAKE2S160,
        Self::ID_BLAKE2S224,
        Self::ID_BLAKE2S256,
        Self::BLAKE3,
        Self::BLAKE3_256,
        Self::ID_SCRYPT,
        Self::ID_ALG_COMPOSITE,
        Self::ID_COMPOSITE_KEY,
        Self::ID_ORACLE_PKCS12_TRUSTED_KEY_USAGE,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
