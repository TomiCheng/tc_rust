//! IANA (PKIX arc and IPsec) identifiers, as Bouncy Castle's
//! `IanaObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.
//!
//! These names repeat an earlier identifier, so `ALL` and `from_oid` give the
//! first name instead:
//! - `ID_MLKEM768_ECDH_BP256_SHA3_256`
//! - `ID_MLKEM1024_ECDH_BP384_SHA3_256`

use tc_asn1::{Asn1Oid, NamedOid};

/// IANA (PKIX arc and IPsec) identifiers.
///
/// ```
/// use tc_asn1_oid::IanaId;
///
/// assert_eq!(IanaId::DIRECTORY.dotted(), "1.3.6.1.1");
/// assert_eq!(
///     IanaId::from_oid(&IanaId::DIRECTORY.oid()),
///     Some(IanaId::DIRECTORY),
/// );
/// ```
pub struct IanaId;

impl IanaId {
    /// Bouncy Castle's `internet`.
    pub const INTERNET: NamedOid = NamedOid::new(&[0x2b, 0x06, 0x01], "1.3.6.1", "internet");

    /// Bouncy Castle's `directory`.
    pub const DIRECTORY: NamedOid =
        NamedOid::new(&[0x2b, 0x06, 0x01, 0x01], "1.3.6.1.1", "directory");

    /// Bouncy Castle's `mgmt`.
    pub const MGMT: NamedOid = NamedOid::new(&[0x2b, 0x06, 0x01, 0x02], "1.3.6.1.2", "mgmt");

    /// Bouncy Castle's `experimental`.
    pub const EXPERIMENTAL: NamedOid =
        NamedOid::new(&[0x2b, 0x06, 0x01, 0x03], "1.3.6.1.3", "experimental");

    /// Bouncy Castle's `cls_private`.
    pub const CLS_PRIVATE: NamedOid =
        NamedOid::new(&[0x2b, 0x06, 0x01, 0x04], "1.3.6.1.4", "cls_private");

    /// Bouncy Castle's `security`.
    pub const SECURITY: NamedOid =
        NamedOid::new(&[0x2b, 0x06, 0x01, 0x05], "1.3.6.1.5", "security");

    /// Bouncy Castle's `SNMPv2`.
    pub const SNMPV2: NamedOid = NamedOid::new(&[0x2b, 0x06, 0x01, 0x06], "1.3.6.1.6", "SNMPv2");

    /// Bouncy Castle's `mail`.
    pub const MAIL: NamedOid = NamedOid::new(&[0x2b, 0x06, 0x01, 0x07], "1.3.6.1.7", "mail");

    /// Bouncy Castle's `kerberosv5`.
    pub const KERBEROSV5: NamedOid =
        NamedOid::new(&[0x2b, 0x06, 0x01, 0x05, 0x02], "1.3.6.1.5.2", "kerberosv5");

    /// Bouncy Castle's `id_pkinit`.
    pub const ID_PKINIT: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03],
        "1.3.6.1.5.2.3",
        "id_pkinit",
    );

    /// Bouncy Castle's `security_mechanisms`.
    pub const SECURITY_MECHANISMS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05],
        "1.3.6.1.5.5",
        "security_mechanisms",
    );

    /// Bouncy Castle's `security_nametypes`.
    pub const SECURITY_NAMETYPES: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x06],
        "1.3.6.1.5.6",
        "security_nametypes",
    );

    /// Bouncy Castle's `pkix`.
    pub const PKIX: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07],
        "1.3.6.1.5.5.7",
        "pkix",
    );

    /// Bouncy Castle's `ipsec`.
    pub const IPSEC: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08],
        "1.3.6.1.5.5.8",
        "ipsec",
    );

    /// Bouncy Castle's `IsakmpOakley`.
    pub const ISAKMP_OAKLEY: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01],
        "1.3.6.1.5.5.8.1",
        "IsakmpOakley",
    );

    /// Bouncy Castle's `HmacMD5`.
    pub const HMAC_MD5: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x01],
        "1.3.6.1.5.5.8.1.1",
        "HmacMD5",
    );

    /// Bouncy Castle's `HmacSha1`.
    pub const HMAC_SHA1: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x02],
        "1.3.6.1.5.5.8.1.2",
        "HmacSha1",
    );

    /// Bouncy Castle's `HmacTiger`.
    pub const HMAC_TIGER: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x03],
        "1.3.6.1.5.5.8.1.3",
        "HmacTiger",
    );

    /// Bouncy Castle's `HmacRipeMD160`.
    pub const HMAC_RIPEMD160: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x04],
        "1.3.6.1.5.5.8.1.4",
        "HmacRipeMD160",
    );

    /// Bouncy Castle's `id_alg`.
    pub const ID_ALG: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06],
        "1.3.6.1.5.5.7.6",
        "id_alg",
    );

    /// Bouncy Castle's `id_RSASSA_PSS_SHAKE128`.
    pub const ID_RSASSA_PSS_SHAKE128: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1e],
        "1.3.6.1.5.5.7.6.30",
        "id_RSASSA_PSS_SHAKE128",
    );

    /// Bouncy Castle's `id_RSASSA_PSS_SHAKE256`.
    pub const ID_RSASSA_PSS_SHAKE256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1f],
        "1.3.6.1.5.5.7.6.31",
        "id_RSASSA_PSS_SHAKE256",
    );

    /// Bouncy Castle's `id_ecdsa_with_shake128`.
    pub const ID_ECDSA_WITH_SHAKE128: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x20],
        "1.3.6.1.5.5.7.6.32",
        "id_ecdsa_with_shake128",
    );

    /// Bouncy Castle's `id_ecdsa_with_shake256`.
    pub const ID_ECDSA_WITH_SHAKE256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x21],
        "1.3.6.1.5.5.7.6.33",
        "id_ecdsa_with_shake256",
    );

    /// Bouncy Castle's `id_alg_xmss_hashsig`.
    pub const ID_ALG_XMSS_HASHSIG: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x22],
        "1.3.6.1.5.5.7.6.34",
        "id_alg_xmss_hashsig",
    );

    /// Bouncy Castle's `id_alg_xmssmt_hashsig`.
    pub const ID_ALG_XMSSMT_HASHSIG: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x23],
        "1.3.6.1.5.5.7.6.35",
        "id_alg_xmssmt_hashsig",
    );

    /// Bouncy Castle's `id_alg_unsigned`.
    pub const ID_ALG_UNSIGNED: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x24],
        "1.3.6.1.5.5.7.6.36",
        "id_alg_unsigned",
    );

    /// Bouncy Castle's `id_MLDSA44_RSA2048_PSS_SHA256`.
    pub const ID_MLDSA44_RSA2048_PSS_SHA256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x25],
        "1.3.6.1.5.5.7.6.37",
        "id_MLDSA44_RSA2048_PSS_SHA256",
    );

    /// Bouncy Castle's `id_MLDSA44_RSA2048_PKCS15_SHA256`.
    pub const ID_MLDSA44_RSA2048_PKCS15_SHA256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x26],
        "1.3.6.1.5.5.7.6.38",
        "id_MLDSA44_RSA2048_PKCS15_SHA256",
    );

    /// Bouncy Castle's `id_MLDSA44_Ed25519_SHA512`.
    pub const ID_MLDSA44_ED25519_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x27],
        "1.3.6.1.5.5.7.6.39",
        "id_MLDSA44_Ed25519_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA44_ECDSA_P256_SHA256`.
    pub const ID_MLDSA44_ECDSA_P256_SHA256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x28],
        "1.3.6.1.5.5.7.6.40",
        "id_MLDSA44_ECDSA_P256_SHA256",
    );

    /// Bouncy Castle's `id_MLDSA65_RSA3072_PSS_SHA512`.
    pub const ID_MLDSA65_RSA3072_PSS_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x29],
        "1.3.6.1.5.5.7.6.41",
        "id_MLDSA65_RSA3072_PSS_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA65_RSA3072_PKCS15_SHA512`.
    pub const ID_MLDSA65_RSA3072_PKCS15_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x2a],
        "1.3.6.1.5.5.7.6.42",
        "id_MLDSA65_RSA3072_PKCS15_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA65_RSA4096_PSS_SHA512`.
    pub const ID_MLDSA65_RSA4096_PSS_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x2b],
        "1.3.6.1.5.5.7.6.43",
        "id_MLDSA65_RSA4096_PSS_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA65_RSA4096_PKCS15_SHA512`.
    pub const ID_MLDSA65_RSA4096_PKCS15_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x2c],
        "1.3.6.1.5.5.7.6.44",
        "id_MLDSA65_RSA4096_PKCS15_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA65_ECDSA_P256_SHA512`.
    pub const ID_MLDSA65_ECDSA_P256_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x2d],
        "1.3.6.1.5.5.7.6.45",
        "id_MLDSA65_ECDSA_P256_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA65_ECDSA_P384_SHA512`.
    pub const ID_MLDSA65_ECDSA_P384_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x2e],
        "1.3.6.1.5.5.7.6.46",
        "id_MLDSA65_ECDSA_P384_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA65_ECDSA_brainpoolP256r1_SHA512`.
    pub const ID_MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x2f],
        "1.3.6.1.5.5.7.6.47",
        "id_MLDSA65_ECDSA_brainpoolP256r1_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA65_Ed25519_SHA512`.
    pub const ID_MLDSA65_ED25519_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x30],
        "1.3.6.1.5.5.7.6.48",
        "id_MLDSA65_Ed25519_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA87_ECDSA_P384_SHA512`.
    pub const ID_MLDSA87_ECDSA_P384_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x31],
        "1.3.6.1.5.5.7.6.49",
        "id_MLDSA87_ECDSA_P384_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA87_ECDSA_brainpoolP384r1_SHA512`.
    pub const ID_MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x32],
        "1.3.6.1.5.5.7.6.50",
        "id_MLDSA87_ECDSA_brainpoolP384r1_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA87_Ed448_SHAKE256`.
    pub const ID_MLDSA87_ED448_SHAKE256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x33],
        "1.3.6.1.5.5.7.6.51",
        "id_MLDSA87_Ed448_SHAKE256",
    );

    /// Bouncy Castle's `id_MLDSA87_RSA3072_PSS_SHA512`.
    pub const ID_MLDSA87_RSA3072_PSS_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x34],
        "1.3.6.1.5.5.7.6.52",
        "id_MLDSA87_RSA3072_PSS_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA87_RSA4096_PSS_SHA512`.
    pub const ID_MLDSA87_RSA4096_PSS_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x35],
        "1.3.6.1.5.5.7.6.53",
        "id_MLDSA87_RSA4096_PSS_SHA512",
    );

    /// Bouncy Castle's `id_MLDSA87_ECDSA_P521_SHA512`.
    pub const ID_MLDSA87_ECDSA_P521_SHA512: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x36],
        "1.3.6.1.5.5.7.6.54",
        "id_MLDSA87_ECDSA_P521_SHA512",
    );

    /// Bouncy Castle's `id_MLKEM768_RSA2048_SHA3_256`.
    pub const ID_MLKEM768_RSA2048_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x37],
        "1.3.6.1.5.5.7.6.55",
        "id_MLKEM768_RSA2048_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM768_RSA3072_SHA3_256`.
    pub const ID_MLKEM768_RSA3072_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x38],
        "1.3.6.1.5.5.7.6.56",
        "id_MLKEM768_RSA3072_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM768_RSA4096_SHA3_256`.
    pub const ID_MLKEM768_RSA4096_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x39],
        "1.3.6.1.5.5.7.6.57",
        "id_MLKEM768_RSA4096_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM768_X25519_SHA3_256`.
    pub const ID_MLKEM768_X25519_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x3a],
        "1.3.6.1.5.5.7.6.58",
        "id_MLKEM768_X25519_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM768_ECDH_P256_SHA3_256`.
    pub const ID_MLKEM768_ECDH_P256_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x3b],
        "1.3.6.1.5.5.7.6.59",
        "id_MLKEM768_ECDH_P256_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM768_ECDH_P384_SHA3_256`.
    pub const ID_MLKEM768_ECDH_P384_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x3c],
        "1.3.6.1.5.5.7.6.60",
        "id_MLKEM768_ECDH_P384_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256`.
    pub const ID_MLKEM768_ECDH_BRAINPOOL_P256R1_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x3d],
        "1.3.6.1.5.5.7.6.61",
        "id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM768_ECDH_BP256_SHA3_256`, the same identifier as [`Self::ID_MLKEM768_ECDH_BRAINPOOL_P256R1_SHA3_256`].
    pub const ID_MLKEM768_ECDH_BP256_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x3d],
        "1.3.6.1.5.5.7.6.61",
        "id_MLKEM768_ECDH_BP256_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM1024_RSA3072_SHA3_256`.
    pub const ID_MLKEM1024_RSA3072_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x3e],
        "1.3.6.1.5.5.7.6.62",
        "id_MLKEM1024_RSA3072_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM1024_ECDH_P384_SHA3_256`.
    pub const ID_MLKEM1024_ECDH_P384_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x3f],
        "1.3.6.1.5.5.7.6.63",
        "id_MLKEM1024_ECDH_P384_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256`.
    pub const ID_MLKEM1024_ECDH_BRAINPOOL_P384R1_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x40],
        "1.3.6.1.5.5.7.6.64",
        "id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM1024_ECDH_BP384_SHA3_256`, the same identifier as [`Self::ID_MLKEM1024_ECDH_BRAINPOOL_P384R1_SHA3_256`].
    pub const ID_MLKEM1024_ECDH_BP384_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x40],
        "1.3.6.1.5.5.7.6.64",
        "id_MLKEM1024_ECDH_BP384_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM1024_X448_SHA3_256`.
    pub const ID_MLKEM1024_X448_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x41],
        "1.3.6.1.5.5.7.6.65",
        "id_MLKEM1024_X448_SHA3_256",
    );

    /// Bouncy Castle's `id_MLKEM1024_ECDH_P521_SHA3_256`.
    pub const ID_MLKEM1024_ECDH_P521_SHA3_256: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x42],
        "1.3.6.1.5.5.7.6.66",
        "id_MLKEM1024_ECDH_P521_SHA3_256",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::INTERNET,
        Self::DIRECTORY,
        Self::MGMT,
        Self::EXPERIMENTAL,
        Self::CLS_PRIVATE,
        Self::SECURITY,
        Self::SNMPV2,
        Self::MAIL,
        Self::KERBEROSV5,
        Self::ID_PKINIT,
        Self::SECURITY_MECHANISMS,
        Self::SECURITY_NAMETYPES,
        Self::PKIX,
        Self::IPSEC,
        Self::ISAKMP_OAKLEY,
        Self::HMAC_MD5,
        Self::HMAC_SHA1,
        Self::HMAC_TIGER,
        Self::HMAC_RIPEMD160,
        Self::ID_ALG,
        Self::ID_RSASSA_PSS_SHAKE128,
        Self::ID_RSASSA_PSS_SHAKE256,
        Self::ID_ECDSA_WITH_SHAKE128,
        Self::ID_ECDSA_WITH_SHAKE256,
        Self::ID_ALG_XMSS_HASHSIG,
        Self::ID_ALG_XMSSMT_HASHSIG,
        Self::ID_ALG_UNSIGNED,
        Self::ID_MLDSA44_RSA2048_PSS_SHA256,
        Self::ID_MLDSA44_RSA2048_PKCS15_SHA256,
        Self::ID_MLDSA44_ED25519_SHA512,
        Self::ID_MLDSA44_ECDSA_P256_SHA256,
        Self::ID_MLDSA65_RSA3072_PSS_SHA512,
        Self::ID_MLDSA65_RSA3072_PKCS15_SHA512,
        Self::ID_MLDSA65_RSA4096_PSS_SHA512,
        Self::ID_MLDSA65_RSA4096_PKCS15_SHA512,
        Self::ID_MLDSA65_ECDSA_P256_SHA512,
        Self::ID_MLDSA65_ECDSA_P384_SHA512,
        Self::ID_MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512,
        Self::ID_MLDSA65_ED25519_SHA512,
        Self::ID_MLDSA87_ECDSA_P384_SHA512,
        Self::ID_MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512,
        Self::ID_MLDSA87_ED448_SHAKE256,
        Self::ID_MLDSA87_RSA3072_PSS_SHA512,
        Self::ID_MLDSA87_RSA4096_PSS_SHA512,
        Self::ID_MLDSA87_ECDSA_P521_SHA512,
        Self::ID_MLKEM768_RSA2048_SHA3_256,
        Self::ID_MLKEM768_RSA3072_SHA3_256,
        Self::ID_MLKEM768_RSA4096_SHA3_256,
        Self::ID_MLKEM768_X25519_SHA3_256,
        Self::ID_MLKEM768_ECDH_P256_SHA3_256,
        Self::ID_MLKEM768_ECDH_P384_SHA3_256,
        Self::ID_MLKEM768_ECDH_BRAINPOOL_P256R1_SHA3_256,
        Self::ID_MLKEM1024_RSA3072_SHA3_256,
        Self::ID_MLKEM1024_ECDH_P384_SHA3_256,
        Self::ID_MLKEM1024_ECDH_BRAINPOOL_P384R1_SHA3_256,
        Self::ID_MLKEM1024_X448_SHA3_256,
        Self::ID_MLKEM1024_ECDH_P521_SHA3_256,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
