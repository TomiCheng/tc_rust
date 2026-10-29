//! NIST algorithm identifiers: hashes, AES, DSA, ECDSA, ML-KEM, ML-DSA,
//! SLH-DSA, as Bouncy Castle's `NistObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.
//!
//! These names repeat an earlier identifier, so `ALL` and `from_oid` give the
//! first name instead:
//! - `ID_DSA_WITH_SHA2`

use tc_asn1::{Asn1Oid, NamedOid};

/// NIST algorithm identifiers: hashes, AES, DSA, ECDSA, ML-KEM, ML-DSA, SLH-DSA.
///
/// ```
/// use tc_asn1_oid::NistId;
///
/// assert_eq!(NistId::HASH_ALGS.dotted(), "2.16.840.1.101.3.4.2");
/// assert_eq!(
///     NistId::from_oid(&NistId::HASH_ALGS.oid()),
///     Some(NistId::HASH_ALGS),
/// );
/// ```
pub struct NistId;

impl NistId {
    /// Bouncy Castle's `NistAlgorithm`.
    pub const NIST_ALGORITHM: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04],
        "2.16.840.1.101.3.4",
        "NistAlgorithm",
    );

    /// Bouncy Castle's `HashAlgs`.
    pub const HASH_ALGS: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02],
        "2.16.840.1.101.3.4.2",
        "HashAlgs",
    );

    /// Bouncy Castle's `IdSha256`.
    pub const ID_SHA256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        "2.16.840.1.101.3.4.2.1",
        "IdSha256",
    );

    /// Bouncy Castle's `IdSha384`.
    pub const ID_SHA384: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
        "2.16.840.1.101.3.4.2.2",
        "IdSha384",
    );

    /// Bouncy Castle's `IdSha512`.
    pub const ID_SHA512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
        "2.16.840.1.101.3.4.2.3",
        "IdSha512",
    );

    /// Bouncy Castle's `IdSha224`.
    pub const ID_SHA224: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
        "2.16.840.1.101.3.4.2.4",
        "IdSha224",
    );

    /// Bouncy Castle's `IdSha512_224`.
    pub const ID_SHA512_224: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05],
        "2.16.840.1.101.3.4.2.5",
        "IdSha512_224",
    );

    /// Bouncy Castle's `IdSha512_256`.
    pub const ID_SHA512_256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06],
        "2.16.840.1.101.3.4.2.6",
        "IdSha512_256",
    );

    /// Bouncy Castle's `IdSha3_224`.
    pub const ID_SHA3_224: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07],
        "2.16.840.1.101.3.4.2.7",
        "IdSha3_224",
    );

    /// Bouncy Castle's `IdSha3_256`.
    pub const ID_SHA3_256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
        "2.16.840.1.101.3.4.2.8",
        "IdSha3_256",
    );

    /// Bouncy Castle's `IdSha3_384`.
    pub const ID_SHA3_384: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
        "2.16.840.1.101.3.4.2.9",
        "IdSha3_384",
    );

    /// Bouncy Castle's `IdSha3_512`.
    pub const ID_SHA3_512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a],
        "2.16.840.1.101.3.4.2.10",
        "IdSha3_512",
    );

    /// Bouncy Castle's `IdShake128`.
    pub const ID_SHAKE128: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b],
        "2.16.840.1.101.3.4.2.11",
        "IdShake128",
    );

    /// Bouncy Castle's `IdShake256`.
    pub const ID_SHAKE256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c],
        "2.16.840.1.101.3.4.2.12",
        "IdShake256",
    );

    /// Bouncy Castle's `IdHMacWithSha3_224`.
    pub const ID_HMAC_WITH_SHA3_224: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0d],
        "2.16.840.1.101.3.4.2.13",
        "IdHMacWithSha3_224",
    );

    /// Bouncy Castle's `IdHMacWithSha3_256`.
    pub const ID_HMAC_WITH_SHA3_256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0e],
        "2.16.840.1.101.3.4.2.14",
        "IdHMacWithSha3_256",
    );

    /// Bouncy Castle's `IdHMacWithSha3_384`.
    pub const ID_HMAC_WITH_SHA3_384: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0f],
        "2.16.840.1.101.3.4.2.15",
        "IdHMacWithSha3_384",
    );

    /// Bouncy Castle's `IdHMacWithSha3_512`.
    pub const ID_HMAC_WITH_SHA3_512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x10],
        "2.16.840.1.101.3.4.2.16",
        "IdHMacWithSha3_512",
    );

    /// Bouncy Castle's `IdShake128Len`.
    pub const ID_SHAKE128_LEN: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x11],
        "2.16.840.1.101.3.4.2.17",
        "IdShake128Len",
    );

    /// Bouncy Castle's `IdShake256Len`.
    pub const ID_SHAKE256_LEN: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x12],
        "2.16.840.1.101.3.4.2.18",
        "IdShake256Len",
    );

    /// Bouncy Castle's `IdKmacWithShake128`.
    pub const ID_KMAC_WITH_SHAKE128: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x13],
        "2.16.840.1.101.3.4.2.19",
        "IdKmacWithShake128",
    );

    /// Bouncy Castle's `IdKmacWithShake256`.
    pub const ID_KMAC_WITH_SHAKE256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x14],
        "2.16.840.1.101.3.4.2.20",
        "IdKmacWithShake256",
    );

    /// Bouncy Castle's `IdKmac128`.
    pub const ID_KMAC128: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x15],
        "2.16.840.1.101.3.4.2.21",
        "IdKmac128",
    );

    /// Bouncy Castle's `IdKmac256`.
    pub const ID_KMAC256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x16],
        "2.16.840.1.101.3.4.2.22",
        "IdKmac256",
    );

    /// Bouncy Castle's `Aes`.
    pub const AES: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01],
        "2.16.840.1.101.3.4.1",
        "Aes",
    );

    /// Bouncy Castle's `IdAes128Ecb`.
    pub const ID_AES128_ECB: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x01],
        "2.16.840.1.101.3.4.1.1",
        "IdAes128Ecb",
    );

    /// Bouncy Castle's `IdAes128Cbc`.
    pub const ID_AES128_CBC: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02],
        "2.16.840.1.101.3.4.1.2",
        "IdAes128Cbc",
    );

    /// Bouncy Castle's `IdAes128Ofb`.
    pub const ID_AES128_OFB: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x03],
        "2.16.840.1.101.3.4.1.3",
        "IdAes128Ofb",
    );

    /// Bouncy Castle's `IdAes128Cfb`.
    pub const ID_AES128_CFB: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x04],
        "2.16.840.1.101.3.4.1.4",
        "IdAes128Cfb",
    );

    /// Bouncy Castle's `IdAes128Wrap`.
    pub const ID_AES128_WRAP: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05],
        "2.16.840.1.101.3.4.1.5",
        "IdAes128Wrap",
    );

    /// Bouncy Castle's `IdAes128Gcm`.
    pub const ID_AES128_GCM: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06],
        "2.16.840.1.101.3.4.1.6",
        "IdAes128Gcm",
    );

    /// Bouncy Castle's `IdAes128Ccm`.
    pub const ID_AES128_CCM: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x07],
        "2.16.840.1.101.3.4.1.7",
        "IdAes128Ccm",
    );

    /// Bouncy Castle's `IdAes128WrapPad`.
    pub const ID_AES128_WRAP_PAD: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x08],
        "2.16.840.1.101.3.4.1.8",
        "IdAes128WrapPad",
    );

    /// Bouncy Castle's `IdAes128GMac`.
    pub const ID_AES128_GMAC: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x09],
        "2.16.840.1.101.3.4.1.9",
        "IdAes128GMac",
    );

    /// Bouncy Castle's `IdAes192Ecb`.
    pub const ID_AES192_ECB: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x15],
        "2.16.840.1.101.3.4.1.21",
        "IdAes192Ecb",
    );

    /// Bouncy Castle's `IdAes192Cbc`.
    pub const ID_AES192_CBC: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16],
        "2.16.840.1.101.3.4.1.22",
        "IdAes192Cbc",
    );

    /// Bouncy Castle's `IdAes192Ofb`.
    pub const ID_AES192_OFB: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x17],
        "2.16.840.1.101.3.4.1.23",
        "IdAes192Ofb",
    );

    /// Bouncy Castle's `IdAes192Cfb`.
    pub const ID_AES192_CFB: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x18],
        "2.16.840.1.101.3.4.1.24",
        "IdAes192Cfb",
    );

    /// Bouncy Castle's `IdAes192Wrap`.
    pub const ID_AES192_WRAP: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x19],
        "2.16.840.1.101.3.4.1.25",
        "IdAes192Wrap",
    );

    /// Bouncy Castle's `IdAes192Gcm`.
    pub const ID_AES192_GCM: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x1a],
        "2.16.840.1.101.3.4.1.26",
        "IdAes192Gcm",
    );

    /// Bouncy Castle's `IdAes192Ccm`.
    pub const ID_AES192_CCM: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x1b],
        "2.16.840.1.101.3.4.1.27",
        "IdAes192Ccm",
    );

    /// Bouncy Castle's `IdAes192WrapPad`.
    pub const ID_AES192_WRAP_PAD: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x1c],
        "2.16.840.1.101.3.4.1.28",
        "IdAes192WrapPad",
    );

    /// Bouncy Castle's `IdAes192GMac`.
    pub const ID_AES192_GMAC: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x1d],
        "2.16.840.1.101.3.4.1.29",
        "IdAes192GMac",
    );

    /// Bouncy Castle's `IdAes256Ecb`.
    pub const ID_AES256_ECB: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x29],
        "2.16.840.1.101.3.4.1.41",
        "IdAes256Ecb",
    );

    /// Bouncy Castle's `IdAes256Cbc`.
    pub const ID_AES256_CBC: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a],
        "2.16.840.1.101.3.4.1.42",
        "IdAes256Cbc",
    );

    /// Bouncy Castle's `IdAes256Ofb`.
    pub const ID_AES256_OFB: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2b],
        "2.16.840.1.101.3.4.1.43",
        "IdAes256Ofb",
    );

    /// Bouncy Castle's `IdAes256Cfb`.
    pub const ID_AES256_CFB: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2c],
        "2.16.840.1.101.3.4.1.44",
        "IdAes256Cfb",
    );

    /// Bouncy Castle's `IdAes256Wrap`.
    pub const ID_AES256_WRAP: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2d],
        "2.16.840.1.101.3.4.1.45",
        "IdAes256Wrap",
    );

    /// Bouncy Castle's `IdAes256Gcm`.
    pub const ID_AES256_GCM: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2e],
        "2.16.840.1.101.3.4.1.46",
        "IdAes256Gcm",
    );

    /// Bouncy Castle's `IdAes256Ccm`.
    pub const ID_AES256_CCM: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2f],
        "2.16.840.1.101.3.4.1.47",
        "IdAes256Ccm",
    );

    /// Bouncy Castle's `IdAes256WrapPad`.
    pub const ID_AES256_WRAP_PAD: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x30],
        "2.16.840.1.101.3.4.1.48",
        "IdAes256WrapPad",
    );

    /// Bouncy Castle's `IdAes256GMac`.
    pub const ID_AES256_GMAC: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x31],
        "2.16.840.1.101.3.4.1.49",
        "IdAes256GMac",
    );

    /// Bouncy Castle's `SigAlgs`.
    pub const SIG_ALGS: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03],
        "2.16.840.1.101.3.4.3",
        "SigAlgs",
    );

    /// Bouncy Castle's `IdDsaWithSha2`, the same identifier as [`Self::SIG_ALGS`].
    pub const ID_DSA_WITH_SHA2: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03],
        "2.16.840.1.101.3.4.3",
        "IdDsaWithSha2",
    );

    /// Bouncy Castle's `DsaWithSha224`.
    pub const DSA_WITH_SHA224: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x01],
        "2.16.840.1.101.3.4.3.1",
        "DsaWithSha224",
    );

    /// Bouncy Castle's `DsaWithSha256`.
    pub const DSA_WITH_SHA256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02],
        "2.16.840.1.101.3.4.3.2",
        "DsaWithSha256",
    );

    /// Bouncy Castle's `DsaWithSha384`.
    pub const DSA_WITH_SHA384: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x03],
        "2.16.840.1.101.3.4.3.3",
        "DsaWithSha384",
    );

    /// Bouncy Castle's `DsaWithSha512`.
    pub const DSA_WITH_SHA512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x04],
        "2.16.840.1.101.3.4.3.4",
        "DsaWithSha512",
    );

    /// Bouncy Castle's `IdDsaWithSha3_224`.
    pub const ID_DSA_WITH_SHA3_224: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x05],
        "2.16.840.1.101.3.4.3.5",
        "IdDsaWithSha3_224",
    );

    /// Bouncy Castle's `IdDsaWithSha3_256`.
    pub const ID_DSA_WITH_SHA3_256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x06],
        "2.16.840.1.101.3.4.3.6",
        "IdDsaWithSha3_256",
    );

    /// Bouncy Castle's `IdDsaWithSha3_384`.
    pub const ID_DSA_WITH_SHA3_384: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x07],
        "2.16.840.1.101.3.4.3.7",
        "IdDsaWithSha3_384",
    );

    /// Bouncy Castle's `IdDsaWithSha3_512`.
    pub const ID_DSA_WITH_SHA3_512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x08],
        "2.16.840.1.101.3.4.3.8",
        "IdDsaWithSha3_512",
    );

    /// Bouncy Castle's `IdEcdsaWithSha3_224`.
    pub const ID_ECDSA_WITH_SHA3_224: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x09],
        "2.16.840.1.101.3.4.3.9",
        "IdEcdsaWithSha3_224",
    );

    /// Bouncy Castle's `IdEcdsaWithSha3_256`.
    pub const ID_ECDSA_WITH_SHA3_256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0a],
        "2.16.840.1.101.3.4.3.10",
        "IdEcdsaWithSha3_256",
    );

    /// Bouncy Castle's `IdEcdsaWithSha3_384`.
    pub const ID_ECDSA_WITH_SHA3_384: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0b],
        "2.16.840.1.101.3.4.3.11",
        "IdEcdsaWithSha3_384",
    );

    /// Bouncy Castle's `IdEcdsaWithSha3_512`.
    pub const ID_ECDSA_WITH_SHA3_512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0c],
        "2.16.840.1.101.3.4.3.12",
        "IdEcdsaWithSha3_512",
    );

    /// Bouncy Castle's `IdRsassaPkcs1V15WithSha3_224`.
    pub const ID_RSASSA_PKCS1V15_WITH_SHA3_224: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0d],
        "2.16.840.1.101.3.4.3.13",
        "IdRsassaPkcs1V15WithSha3_224",
    );

    /// Bouncy Castle's `IdRsassaPkcs1V15WithSha3_256`.
    pub const ID_RSASSA_PKCS1V15_WITH_SHA3_256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0e],
        "2.16.840.1.101.3.4.3.14",
        "IdRsassaPkcs1V15WithSha3_256",
    );

    /// Bouncy Castle's `IdRsassaPkcs1V15WithSha3_384`.
    pub const ID_RSASSA_PKCS1V15_WITH_SHA3_384: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0f],
        "2.16.840.1.101.3.4.3.15",
        "IdRsassaPkcs1V15WithSha3_384",
    );

    /// Bouncy Castle's `IdRsassaPkcs1V15WithSha3_512`.
    pub const ID_RSASSA_PKCS1V15_WITH_SHA3_512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10],
        "2.16.840.1.101.3.4.3.16",
        "IdRsassaPkcs1V15WithSha3_512",
    );

    /// Bouncy Castle's `id_ml_dsa_44`.
    pub const ID_ML_DSA_44: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11],
        "2.16.840.1.101.3.4.3.17",
        "id_ml_dsa_44",
    );

    /// Bouncy Castle's `id_ml_dsa_65`.
    pub const ID_ML_DSA_65: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12],
        "2.16.840.1.101.3.4.3.18",
        "id_ml_dsa_65",
    );

    /// Bouncy Castle's `id_ml_dsa_87`.
    pub const ID_ML_DSA_87: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13],
        "2.16.840.1.101.3.4.3.19",
        "id_ml_dsa_87",
    );

    /// Bouncy Castle's `id_hash_ml_dsa_44_with_sha512`.
    pub const ID_HASH_ML_DSA_44_WITH_SHA512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x20],
        "2.16.840.1.101.3.4.3.32",
        "id_hash_ml_dsa_44_with_sha512",
    );

    /// Bouncy Castle's `id_hash_ml_dsa_65_with_sha512`.
    pub const ID_HASH_ML_DSA_65_WITH_SHA512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x21],
        "2.16.840.1.101.3.4.3.33",
        "id_hash_ml_dsa_65_with_sha512",
    );

    /// Bouncy Castle's `id_hash_ml_dsa_87_with_sha512`.
    pub const ID_HASH_ML_DSA_87_WITH_SHA512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x22],
        "2.16.840.1.101.3.4.3.34",
        "id_hash_ml_dsa_87_with_sha512",
    );

    /// Bouncy Castle's `id_slh_dsa_sha2_128s`.
    pub const ID_SLH_DSA_SHA2_128S: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14],
        "2.16.840.1.101.3.4.3.20",
        "id_slh_dsa_sha2_128s",
    );

    /// Bouncy Castle's `id_slh_dsa_sha2_128f`.
    pub const ID_SLH_DSA_SHA2_128F: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x15],
        "2.16.840.1.101.3.4.3.21",
        "id_slh_dsa_sha2_128f",
    );

    /// Bouncy Castle's `id_slh_dsa_sha2_192s`.
    pub const ID_SLH_DSA_SHA2_192S: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x16],
        "2.16.840.1.101.3.4.3.22",
        "id_slh_dsa_sha2_192s",
    );

    /// Bouncy Castle's `id_slh_dsa_sha2_192f`.
    pub const ID_SLH_DSA_SHA2_192F: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x17],
        "2.16.840.1.101.3.4.3.23",
        "id_slh_dsa_sha2_192f",
    );

    /// Bouncy Castle's `id_slh_dsa_sha2_256s`.
    pub const ID_SLH_DSA_SHA2_256S: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x18],
        "2.16.840.1.101.3.4.3.24",
        "id_slh_dsa_sha2_256s",
    );

    /// Bouncy Castle's `id_slh_dsa_sha2_256f`.
    pub const ID_SLH_DSA_SHA2_256F: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x19],
        "2.16.840.1.101.3.4.3.25",
        "id_slh_dsa_sha2_256f",
    );

    /// Bouncy Castle's `id_slh_dsa_shake_128s`.
    pub const ID_SLH_DSA_SHAKE_128S: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1a],
        "2.16.840.1.101.3.4.3.26",
        "id_slh_dsa_shake_128s",
    );

    /// Bouncy Castle's `id_slh_dsa_shake_128f`.
    pub const ID_SLH_DSA_SHAKE_128F: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1b],
        "2.16.840.1.101.3.4.3.27",
        "id_slh_dsa_shake_128f",
    );

    /// Bouncy Castle's `id_slh_dsa_shake_192s`.
    pub const ID_SLH_DSA_SHAKE_192S: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1c],
        "2.16.840.1.101.3.4.3.28",
        "id_slh_dsa_shake_192s",
    );

    /// Bouncy Castle's `id_slh_dsa_shake_192f`.
    pub const ID_SLH_DSA_SHAKE_192F: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1d],
        "2.16.840.1.101.3.4.3.29",
        "id_slh_dsa_shake_192f",
    );

    /// Bouncy Castle's `id_slh_dsa_shake_256s`.
    pub const ID_SLH_DSA_SHAKE_256S: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1e],
        "2.16.840.1.101.3.4.3.30",
        "id_slh_dsa_shake_256s",
    );

    /// Bouncy Castle's `id_slh_dsa_shake_256f`.
    pub const ID_SLH_DSA_SHAKE_256F: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1f],
        "2.16.840.1.101.3.4.3.31",
        "id_slh_dsa_shake_256f",
    );

    /// Bouncy Castle's `id_hash_slh_dsa_sha2_128s_with_sha256`.
    pub const ID_HASH_SLH_DSA_SHA2_128S_WITH_SHA256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x23],
        "2.16.840.1.101.3.4.3.35",
        "id_hash_slh_dsa_sha2_128s_with_sha256",
    );

    /// Bouncy Castle's `id_hash_slh_dsa_sha2_128f_with_sha256`.
    pub const ID_HASH_SLH_DSA_SHA2_128F_WITH_SHA256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x24],
        "2.16.840.1.101.3.4.3.36",
        "id_hash_slh_dsa_sha2_128f_with_sha256",
    );

    /// Bouncy Castle's `id_hash_slh_dsa_sha2_192s_with_sha512`.
    pub const ID_HASH_SLH_DSA_SHA2_192S_WITH_SHA512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x25],
        "2.16.840.1.101.3.4.3.37",
        "id_hash_slh_dsa_sha2_192s_with_sha512",
    );

    /// Bouncy Castle's `id_hash_slh_dsa_sha2_192f_with_sha512`.
    pub const ID_HASH_SLH_DSA_SHA2_192F_WITH_SHA512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x26],
        "2.16.840.1.101.3.4.3.38",
        "id_hash_slh_dsa_sha2_192f_with_sha512",
    );

    /// Bouncy Castle's `id_hash_slh_dsa_sha2_256s_with_sha512`.
    pub const ID_HASH_SLH_DSA_SHA2_256S_WITH_SHA512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x27],
        "2.16.840.1.101.3.4.3.39",
        "id_hash_slh_dsa_sha2_256s_with_sha512",
    );

    /// Bouncy Castle's `id_hash_slh_dsa_sha2_256f_with_sha512`.
    pub const ID_HASH_SLH_DSA_SHA2_256F_WITH_SHA512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x28],
        "2.16.840.1.101.3.4.3.40",
        "id_hash_slh_dsa_sha2_256f_with_sha512",
    );

    /// Bouncy Castle's `id_hash_slh_dsa_shake_128s_with_shake128`.
    pub const ID_HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x29],
        "2.16.840.1.101.3.4.3.41",
        "id_hash_slh_dsa_shake_128s_with_shake128",
    );

    /// Bouncy Castle's `id_hash_slh_dsa_shake_128f_with_shake128`.
    pub const ID_HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x2a],
        "2.16.840.1.101.3.4.3.42",
        "id_hash_slh_dsa_shake_128f_with_shake128",
    );

    /// Bouncy Castle's `id_hash_slh_dsa_shake_192s_with_shake256`.
    pub const ID_HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x2b],
        "2.16.840.1.101.3.4.3.43",
        "id_hash_slh_dsa_shake_192s_with_shake256",
    );

    /// Bouncy Castle's `id_hash_slh_dsa_shake_192f_with_shake256`.
    pub const ID_HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x2c],
        "2.16.840.1.101.3.4.3.44",
        "id_hash_slh_dsa_shake_192f_with_shake256",
    );

    /// Bouncy Castle's `id_hash_slh_dsa_shake_256s_with_shake256`.
    pub const ID_HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x2d],
        "2.16.840.1.101.3.4.3.45",
        "id_hash_slh_dsa_shake_256s_with_shake256",
    );

    /// Bouncy Castle's `id_hash_slh_dsa_shake_256f_with_shake256`.
    pub const ID_HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x2e],
        "2.16.840.1.101.3.4.3.46",
        "id_hash_slh_dsa_shake_256f_with_shake256",
    );

    /// Bouncy Castle's `kems`.
    pub const KEMS: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04],
        "2.16.840.1.101.3.4.4",
        "kems",
    );

    /// Bouncy Castle's `id_alg_ml_kem_512`.
    pub const ID_ALG_ML_KEM_512: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01],
        "2.16.840.1.101.3.4.4.1",
        "id_alg_ml_kem_512",
    );

    /// Bouncy Castle's `id_alg_ml_kem_768`.
    pub const ID_ALG_ML_KEM_768: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02],
        "2.16.840.1.101.3.4.4.2",
        "id_alg_ml_kem_768",
    );

    /// Bouncy Castle's `id_alg_ml_kem_1024`.
    pub const ID_ALG_ML_KEM_1024: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03],
        "2.16.840.1.101.3.4.4.3",
        "id_alg_ml_kem_1024",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::NIST_ALGORITHM,
        Self::HASH_ALGS,
        Self::ID_SHA256,
        Self::ID_SHA384,
        Self::ID_SHA512,
        Self::ID_SHA224,
        Self::ID_SHA512_224,
        Self::ID_SHA512_256,
        Self::ID_SHA3_224,
        Self::ID_SHA3_256,
        Self::ID_SHA3_384,
        Self::ID_SHA3_512,
        Self::ID_SHAKE128,
        Self::ID_SHAKE256,
        Self::ID_HMAC_WITH_SHA3_224,
        Self::ID_HMAC_WITH_SHA3_256,
        Self::ID_HMAC_WITH_SHA3_384,
        Self::ID_HMAC_WITH_SHA3_512,
        Self::ID_SHAKE128_LEN,
        Self::ID_SHAKE256_LEN,
        Self::ID_KMAC_WITH_SHAKE128,
        Self::ID_KMAC_WITH_SHAKE256,
        Self::ID_KMAC128,
        Self::ID_KMAC256,
        Self::AES,
        Self::ID_AES128_ECB,
        Self::ID_AES128_CBC,
        Self::ID_AES128_OFB,
        Self::ID_AES128_CFB,
        Self::ID_AES128_WRAP,
        Self::ID_AES128_GCM,
        Self::ID_AES128_CCM,
        Self::ID_AES128_WRAP_PAD,
        Self::ID_AES128_GMAC,
        Self::ID_AES192_ECB,
        Self::ID_AES192_CBC,
        Self::ID_AES192_OFB,
        Self::ID_AES192_CFB,
        Self::ID_AES192_WRAP,
        Self::ID_AES192_GCM,
        Self::ID_AES192_CCM,
        Self::ID_AES192_WRAP_PAD,
        Self::ID_AES192_GMAC,
        Self::ID_AES256_ECB,
        Self::ID_AES256_CBC,
        Self::ID_AES256_OFB,
        Self::ID_AES256_CFB,
        Self::ID_AES256_WRAP,
        Self::ID_AES256_GCM,
        Self::ID_AES256_CCM,
        Self::ID_AES256_WRAP_PAD,
        Self::ID_AES256_GMAC,
        Self::SIG_ALGS,
        Self::DSA_WITH_SHA224,
        Self::DSA_WITH_SHA256,
        Self::DSA_WITH_SHA384,
        Self::DSA_WITH_SHA512,
        Self::ID_DSA_WITH_SHA3_224,
        Self::ID_DSA_WITH_SHA3_256,
        Self::ID_DSA_WITH_SHA3_384,
        Self::ID_DSA_WITH_SHA3_512,
        Self::ID_ECDSA_WITH_SHA3_224,
        Self::ID_ECDSA_WITH_SHA3_256,
        Self::ID_ECDSA_WITH_SHA3_384,
        Self::ID_ECDSA_WITH_SHA3_512,
        Self::ID_RSASSA_PKCS1V15_WITH_SHA3_224,
        Self::ID_RSASSA_PKCS1V15_WITH_SHA3_256,
        Self::ID_RSASSA_PKCS1V15_WITH_SHA3_384,
        Self::ID_RSASSA_PKCS1V15_WITH_SHA3_512,
        Self::ID_ML_DSA_44,
        Self::ID_ML_DSA_65,
        Self::ID_ML_DSA_87,
        Self::ID_HASH_ML_DSA_44_WITH_SHA512,
        Self::ID_HASH_ML_DSA_65_WITH_SHA512,
        Self::ID_HASH_ML_DSA_87_WITH_SHA512,
        Self::ID_SLH_DSA_SHA2_128S,
        Self::ID_SLH_DSA_SHA2_128F,
        Self::ID_SLH_DSA_SHA2_192S,
        Self::ID_SLH_DSA_SHA2_192F,
        Self::ID_SLH_DSA_SHA2_256S,
        Self::ID_SLH_DSA_SHA2_256F,
        Self::ID_SLH_DSA_SHAKE_128S,
        Self::ID_SLH_DSA_SHAKE_128F,
        Self::ID_SLH_DSA_SHAKE_192S,
        Self::ID_SLH_DSA_SHAKE_192F,
        Self::ID_SLH_DSA_SHAKE_256S,
        Self::ID_SLH_DSA_SHAKE_256F,
        Self::ID_HASH_SLH_DSA_SHA2_128S_WITH_SHA256,
        Self::ID_HASH_SLH_DSA_SHA2_128F_WITH_SHA256,
        Self::ID_HASH_SLH_DSA_SHA2_192S_WITH_SHA512,
        Self::ID_HASH_SLH_DSA_SHA2_192F_WITH_SHA512,
        Self::ID_HASH_SLH_DSA_SHA2_256S_WITH_SHA512,
        Self::ID_HASH_SLH_DSA_SHA2_256F_WITH_SHA512,
        Self::ID_HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128,
        Self::ID_HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128,
        Self::ID_HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256,
        Self::ID_HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256,
        Self::ID_HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256,
        Self::ID_HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256,
        Self::KEMS,
        Self::ID_ALG_ML_KEM_512,
        Self::ID_ALG_ML_KEM_768,
        Self::ID_ALG_ML_KEM_1024,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
