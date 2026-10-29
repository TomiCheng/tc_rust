//! Chinese GM/T (SM2, SM3, SM4 and friends) identifiers, as Bouncy Castle's
//! `GMObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// Chinese GM/T (SM2, SM3, SM4 and friends) identifiers.
///
/// ```
/// use tc_asn1_oid::GmId;
///
/// assert_eq!(GmId::SM6_ECB.dotted(), "1.2.156.10197.1.101.1");
/// assert_eq!(
///     GmId::from_oid(&GmId::SM6_ECB.oid()),
///     Some(GmId::SM6_ECB),
/// );
/// ```
pub struct GmId;

impl GmId {
    /// Bouncy Castle's `sm_scheme`.
    pub const SM_SCHEME: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01],
        "1.2.156.10197.1",
        "sm_scheme",
    );

    /// Bouncy Castle's `sm6_ecb`.
    pub const SM6_ECB: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x65, 0x01],
        "1.2.156.10197.1.101.1",
        "sm6_ecb",
    );

    /// Bouncy Castle's `sm6_cbc`.
    pub const SM6_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x65, 0x02],
        "1.2.156.10197.1.101.2",
        "sm6_cbc",
    );

    /// Bouncy Castle's `sm6_ofb128`.
    pub const SM6_OFB128: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x65, 0x03],
        "1.2.156.10197.1.101.3",
        "sm6_ofb128",
    );

    /// Bouncy Castle's `sm6_cfb128`.
    pub const SM6_CFB128: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x65, 0x04],
        "1.2.156.10197.1.101.4",
        "sm6_cfb128",
    );

    /// Bouncy Castle's `sm1_ecb`.
    pub const SM1_ECB: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x66, 0x01],
        "1.2.156.10197.1.102.1",
        "sm1_ecb",
    );

    /// Bouncy Castle's `sm1_cbc`.
    pub const SM1_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x66, 0x02],
        "1.2.156.10197.1.102.2",
        "sm1_cbc",
    );

    /// Bouncy Castle's `sm1_ofb128`.
    pub const SM1_OFB128: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x66, 0x03],
        "1.2.156.10197.1.102.3",
        "sm1_ofb128",
    );

    /// Bouncy Castle's `sm1_cfb128`.
    pub const SM1_CFB128: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x66, 0x04],
        "1.2.156.10197.1.102.4",
        "sm1_cfb128",
    );

    /// Bouncy Castle's `sm1_cfb1`.
    pub const SM1_CFB1: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x66, 0x05],
        "1.2.156.10197.1.102.5",
        "sm1_cfb1",
    );

    /// Bouncy Castle's `sm1_cfb8`.
    pub const SM1_CFB8: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x66, 0x06],
        "1.2.156.10197.1.102.6",
        "sm1_cfb8",
    );

    /// Bouncy Castle's `ssf33_ecb`.
    pub const SSF33_ECB: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x67, 0x01],
        "1.2.156.10197.1.103.1",
        "ssf33_ecb",
    );

    /// Bouncy Castle's `ssf33_cbc`.
    pub const SSF33_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x67, 0x02],
        "1.2.156.10197.1.103.2",
        "ssf33_cbc",
    );

    /// Bouncy Castle's `ssf33_ofb128`.
    pub const SSF33_OFB128: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x67, 0x03],
        "1.2.156.10197.1.103.3",
        "ssf33_ofb128",
    );

    /// Bouncy Castle's `ssf33_cfb128`.
    pub const SSF33_CFB128: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x67, 0x04],
        "1.2.156.10197.1.103.4",
        "ssf33_cfb128",
    );

    /// Bouncy Castle's `ssf33_cfb1`.
    pub const SSF33_CFB1: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x67, 0x05],
        "1.2.156.10197.1.103.5",
        "ssf33_cfb1",
    );

    /// Bouncy Castle's `ssf33_cfb8`.
    pub const SSF33_CFB8: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x67, 0x06],
        "1.2.156.10197.1.103.6",
        "ssf33_cfb8",
    );

    /// Bouncy Castle's `sms4_ecb`.
    pub const SMS4_ECB: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x01],
        "1.2.156.10197.1.104.1",
        "sms4_ecb",
    );

    /// Bouncy Castle's `sms4_cbc`.
    pub const SMS4_CBC: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x02],
        "1.2.156.10197.1.104.2",
        "sms4_cbc",
    );

    /// Bouncy Castle's `sms4_ofb128`.
    pub const SMS4_OFB128: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x03],
        "1.2.156.10197.1.104.3",
        "sms4_ofb128",
    );

    /// Bouncy Castle's `sms4_cfb128`.
    pub const SMS4_CFB128: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x04],
        "1.2.156.10197.1.104.4",
        "sms4_cfb128",
    );

    /// Bouncy Castle's `sms4_cfb1`.
    pub const SMS4_CFB1: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x05],
        "1.2.156.10197.1.104.5",
        "sms4_cfb1",
    );

    /// Bouncy Castle's `sms4_cfb8`.
    pub const SMS4_CFB8: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x06],
        "1.2.156.10197.1.104.6",
        "sms4_cfb8",
    );

    /// Bouncy Castle's `sms4_ctr`.
    pub const SMS4_CTR: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x07],
        "1.2.156.10197.1.104.7",
        "sms4_ctr",
    );

    /// Bouncy Castle's `sms4_gcm`.
    pub const SMS4_GCM: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x08],
        "1.2.156.10197.1.104.8",
        "sms4_gcm",
    );

    /// Bouncy Castle's `sms4_ccm`.
    pub const SMS4_CCM: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x09],
        "1.2.156.10197.1.104.9",
        "sms4_ccm",
    );

    /// Bouncy Castle's `sms4_xts`.
    pub const SMS4_XTS: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x0a],
        "1.2.156.10197.1.104.10",
        "sms4_xts",
    );

    /// Bouncy Castle's `sms4_wrap`.
    pub const SMS4_WRAP: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x0b],
        "1.2.156.10197.1.104.11",
        "sms4_wrap",
    );

    /// Bouncy Castle's `sms4_wrap_pad`.
    pub const SMS4_WRAP_PAD: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x0c],
        "1.2.156.10197.1.104.12",
        "sms4_wrap_pad",
    );

    /// Bouncy Castle's `sms4_ocb`.
    pub const SMS4_OCB: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x64],
        "1.2.156.10197.1.104.100",
        "sms4_ocb",
    );

    /// Bouncy Castle's `sm5`.
    pub const SM5: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x81, 0x49],
        "1.2.156.10197.1.201",
        "sm5",
    );

    /// Bouncy Castle's `sm2p256v1`.
    pub const SM2P256V1: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d],
        "1.2.156.10197.1.301",
        "sm2p256v1",
    );

    /// Bouncy Castle's `sm2sign`.
    pub const SM2SIGN: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x01],
        "1.2.156.10197.1.301.1",
        "sm2sign",
    );

    /// Bouncy Castle's `sm2exchange`.
    pub const SM2EXCHANGE: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x02],
        "1.2.156.10197.1.301.2",
        "sm2exchange",
    );

    /// Bouncy Castle's `sm2encrypt`.
    pub const SM2ENCRYPT: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03],
        "1.2.156.10197.1.301.3",
        "sm2encrypt",
    );

    /// Bouncy Castle's `wapip192v1`.
    pub const WAPIP192V1: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x65],
        "1.2.156.10197.1.301.101",
        "wapip192v1",
    );

    /// Bouncy Castle's `wapi192v1`.
    pub const WAPI192V1: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xd7, 0x63, 0x01, 0x01, 0x01],
        "1.2.156.11235.1.1.1",
        "wapi192v1",
    );

    /// Bouncy Castle's `wapi192v1_parameters`.
    pub const WAPI192V1_PARAMETERS: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xd7, 0x63, 0x01, 0x01, 0x02, 0x01],
        "1.2.156.11235.1.1.2.1",
        "wapi192v1_parameters",
    );

    /// Bouncy Castle's `sm2encrypt_recommendedParameters`.
    pub const SM2ENCRYPT_RECOMMENDED_PARAMETERS: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x01],
        "1.2.156.10197.1.301.3.1",
        "sm2encrypt_recommendedParameters",
    );

    /// Bouncy Castle's `sm2encrypt_specifiedParameters`.
    pub const SM2ENCRYPT_SPECIFIED_PARAMETERS: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x02],
        "1.2.156.10197.1.301.3.2",
        "sm2encrypt_specifiedParameters",
    );

    /// Bouncy Castle's `sm2encrypt_with_sm3`.
    pub const SM2ENCRYPT_WITH_SM3: NamedOid = NamedOid::new(
        &[
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x02, 0x01,
        ],
        "1.2.156.10197.1.301.3.2.1",
        "sm2encrypt_with_sm3",
    );

    /// Bouncy Castle's `sm2encrypt_with_sha1`.
    pub const SM2ENCRYPT_WITH_SHA1: NamedOid = NamedOid::new(
        &[
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x02, 0x02,
        ],
        "1.2.156.10197.1.301.3.2.2",
        "sm2encrypt_with_sha1",
    );

    /// Bouncy Castle's `sm2encrypt_with_sha224`.
    pub const SM2ENCRYPT_WITH_SHA224: NamedOid = NamedOid::new(
        &[
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x02, 0x03,
        ],
        "1.2.156.10197.1.301.3.2.3",
        "sm2encrypt_with_sha224",
    );

    /// Bouncy Castle's `sm2encrypt_with_sha256`.
    pub const SM2ENCRYPT_WITH_SHA256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x02, 0x04,
        ],
        "1.2.156.10197.1.301.3.2.4",
        "sm2encrypt_with_sha256",
    );

    /// Bouncy Castle's `sm2encrypt_with_sha384`.
    pub const SM2ENCRYPT_WITH_SHA384: NamedOid = NamedOid::new(
        &[
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x02, 0x05,
        ],
        "1.2.156.10197.1.301.3.2.5",
        "sm2encrypt_with_sha384",
    );

    /// Bouncy Castle's `sm2encrypt_with_sha512`.
    pub const SM2ENCRYPT_WITH_SHA512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x02, 0x06,
        ],
        "1.2.156.10197.1.301.3.2.6",
        "sm2encrypt_with_sha512",
    );

    /// Bouncy Castle's `sm2encrypt_with_rmd160`.
    pub const SM2ENCRYPT_WITH_RMD160: NamedOid = NamedOid::new(
        &[
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x02, 0x07,
        ],
        "1.2.156.10197.1.301.3.2.7",
        "sm2encrypt_with_rmd160",
    );

    /// Bouncy Castle's `sm2encrypt_with_whirlpool`.
    pub const SM2ENCRYPT_WITH_WHIRLPOOL: NamedOid = NamedOid::new(
        &[
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x02, 0x08,
        ],
        "1.2.156.10197.1.301.3.2.8",
        "sm2encrypt_with_whirlpool",
    );

    /// Bouncy Castle's `sm2encrypt_with_blake2b512`.
    pub const SM2ENCRYPT_WITH_BLAKE2B512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x02, 0x09,
        ],
        "1.2.156.10197.1.301.3.2.9",
        "sm2encrypt_with_blake2b512",
    );

    /// Bouncy Castle's `sm2encrypt_with_blake2s256`.
    pub const SM2ENCRYPT_WITH_BLAKE2S256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x02, 0x0a,
        ],
        "1.2.156.10197.1.301.3.2.10",
        "sm2encrypt_with_blake2s256",
    );

    /// Bouncy Castle's `sm2encrypt_with_md5`.
    pub const SM2ENCRYPT_WITH_MD5: NamedOid = NamedOid::new(
        &[
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x02, 0x0b,
        ],
        "1.2.156.10197.1.301.3.2.11",
        "sm2encrypt_with_md5",
    );

    /// Bouncy Castle's `id_sm9PublicKey`.
    pub const ID_SM9_PUBLIC_KEY: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2e],
        "1.2.156.10197.1.302",
        "id_sm9PublicKey",
    );

    /// Bouncy Castle's `sm9sign`.
    pub const SM9SIGN: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2e, 0x01],
        "1.2.156.10197.1.302.1",
        "sm9sign",
    );

    /// Bouncy Castle's `sm9keyagreement`.
    pub const SM9KEYAGREEMENT: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2e, 0x02],
        "1.2.156.10197.1.302.2",
        "sm9keyagreement",
    );

    /// Bouncy Castle's `sm9encrypt`.
    pub const SM9ENCRYPT: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2e, 0x03],
        "1.2.156.10197.1.302.3",
        "sm9encrypt",
    );

    /// Bouncy Castle's `sm3`.
    pub const SM3: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x11],
        "1.2.156.10197.1.401",
        "sm3",
    );

    /// Bouncy Castle's `hmac_sm3`.
    pub const HMAC_SM3: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x11, 0x02],
        "1.2.156.10197.1.401.2",
        "hmac_sm3",
    );

    /// Bouncy Castle's `sm2sign_with_sm3`.
    pub const SM2SIGN_WITH_SM3: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75],
        "1.2.156.10197.1.501",
        "sm2sign_with_sm3",
    );

    /// Bouncy Castle's `sm2sign_with_sha1`.
    pub const SM2SIGN_WITH_SHA1: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x76],
        "1.2.156.10197.1.502",
        "sm2sign_with_sha1",
    );

    /// Bouncy Castle's `sm2sign_with_sha256`.
    pub const SM2SIGN_WITH_SHA256: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x77],
        "1.2.156.10197.1.503",
        "sm2sign_with_sha256",
    );

    /// Bouncy Castle's `sm2sign_with_sha512`.
    pub const SM2SIGN_WITH_SHA512: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x78],
        "1.2.156.10197.1.504",
        "sm2sign_with_sha512",
    );

    /// Bouncy Castle's `sm2sign_with_sha224`.
    pub const SM2SIGN_WITH_SHA224: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x79],
        "1.2.156.10197.1.505",
        "sm2sign_with_sha224",
    );

    /// Bouncy Castle's `sm2sign_with_sha384`.
    pub const SM2SIGN_WITH_SHA384: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x7a],
        "1.2.156.10197.1.506",
        "sm2sign_with_sha384",
    );

    /// Bouncy Castle's `sm2sign_with_rmd160`.
    pub const SM2SIGN_WITH_RMD160: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x7b],
        "1.2.156.10197.1.507",
        "sm2sign_with_rmd160",
    );

    /// Bouncy Castle's `sm2sign_with_whirlpool`.
    pub const SM2SIGN_WITH_WHIRLPOOL: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x84, 0x08],
        "1.2.156.10197.1.520",
        "sm2sign_with_whirlpool",
    );

    /// Bouncy Castle's `sm2sign_with_blake2b512`.
    pub const SM2SIGN_WITH_BLAKE2B512: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x84, 0x09],
        "1.2.156.10197.1.521",
        "sm2sign_with_blake2b512",
    );

    /// Bouncy Castle's `sm2sign_with_blake2s256`.
    pub const SM2SIGN_WITH_BLAKE2S256: NamedOid = NamedOid::new(
        &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x84, 0x0a],
        "1.2.156.10197.1.522",
        "sm2sign_with_blake2s256",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::SM_SCHEME,
        Self::SM6_ECB,
        Self::SM6_CBC,
        Self::SM6_OFB128,
        Self::SM6_CFB128,
        Self::SM1_ECB,
        Self::SM1_CBC,
        Self::SM1_OFB128,
        Self::SM1_CFB128,
        Self::SM1_CFB1,
        Self::SM1_CFB8,
        Self::SSF33_ECB,
        Self::SSF33_CBC,
        Self::SSF33_OFB128,
        Self::SSF33_CFB128,
        Self::SSF33_CFB1,
        Self::SSF33_CFB8,
        Self::SMS4_ECB,
        Self::SMS4_CBC,
        Self::SMS4_OFB128,
        Self::SMS4_CFB128,
        Self::SMS4_CFB1,
        Self::SMS4_CFB8,
        Self::SMS4_CTR,
        Self::SMS4_GCM,
        Self::SMS4_CCM,
        Self::SMS4_XTS,
        Self::SMS4_WRAP,
        Self::SMS4_WRAP_PAD,
        Self::SMS4_OCB,
        Self::SM5,
        Self::SM2P256V1,
        Self::SM2SIGN,
        Self::SM2EXCHANGE,
        Self::SM2ENCRYPT,
        Self::WAPIP192V1,
        Self::WAPI192V1,
        Self::WAPI192V1_PARAMETERS,
        Self::SM2ENCRYPT_RECOMMENDED_PARAMETERS,
        Self::SM2ENCRYPT_SPECIFIED_PARAMETERS,
        Self::SM2ENCRYPT_WITH_SM3,
        Self::SM2ENCRYPT_WITH_SHA1,
        Self::SM2ENCRYPT_WITH_SHA224,
        Self::SM2ENCRYPT_WITH_SHA256,
        Self::SM2ENCRYPT_WITH_SHA384,
        Self::SM2ENCRYPT_WITH_SHA512,
        Self::SM2ENCRYPT_WITH_RMD160,
        Self::SM2ENCRYPT_WITH_WHIRLPOOL,
        Self::SM2ENCRYPT_WITH_BLAKE2B512,
        Self::SM2ENCRYPT_WITH_BLAKE2S256,
        Self::SM2ENCRYPT_WITH_MD5,
        Self::ID_SM9_PUBLIC_KEY,
        Self::SM9SIGN,
        Self::SM9KEYAGREEMENT,
        Self::SM9ENCRYPT,
        Self::SM3,
        Self::HMAC_SM3,
        Self::SM2SIGN_WITH_SM3,
        Self::SM2SIGN_WITH_SHA1,
        Self::SM2SIGN_WITH_SHA256,
        Self::SM2SIGN_WITH_SHA512,
        Self::SM2SIGN_WITH_SHA224,
        Self::SM2SIGN_WITH_SHA384,
        Self::SM2SIGN_WITH_RMD160,
        Self::SM2SIGN_WITH_WHIRLPOOL,
        Self::SM2SIGN_WITH_BLAKE2B512,
        Self::SM2SIGN_WITH_BLAKE2S256,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
