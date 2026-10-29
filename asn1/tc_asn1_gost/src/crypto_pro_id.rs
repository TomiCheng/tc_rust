//! CryptoPro identifiers (RFC 4357), as Bouncy Castle's
//! `CryptoProObjectIdentifiers` names them.
//!
//! Bouncy Castle's aliases `GostR28147Cbc`, `GostElSgDH3410Default` and
//! `GostElSgDH3410x1` repeat `GOST_R28147_GCFB` and the two exchange parameter
//! sets, so they are left out. This table names known identifiers without
//! restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// GOST R 34.10-94/2001, GOST R 34.11-94 and GOST 28147-89 identifiers.
///
/// ```
/// use tc_asn1_gost::CryptoProId;
///
/// assert_eq!(CryptoProId::GOST28147_89_CRYPTO_PRO_A_PARAM_SET.dotted(), "1.2.643.2.2.31.1");
/// assert_eq!(
///     CryptoProId::from_oid(&CryptoProId::GOST_ID.oid()),
///     Some(CryptoProId::GOST_ID),
/// );
/// ```
pub struct CryptoProId;

impl CryptoProId {
    /// The CryptoPro arc.
    pub const GOST_ID: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02],
        "1.2.643.2.2",
        "id-CryptoPro",
    );

    /// GOST R 34.11-94.
    pub const GOST_R3411: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x09],
        "1.2.643.2.2.9",
        "id-GostR3411-94",
    );

    /// HMAC with GOST R 34.11-94.
    pub const GOST_R3411_HMAC: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x0a],
        "1.2.643.2.2.10",
        "id-HMACGostR3411-94",
    );

    /// GOST 28147-89 key wrap.
    pub const GOST28147_89_NONE_KEY_WRAP: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x0d, 0x00],
        "1.2.643.2.2.13.0",
        "id-Gost28147-89-None-KeyWrap",
    );

    /// CryptoPro key wrap.
    pub const GOST28147_89_CRYPTO_PRO_KEY_WRAP: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x0d, 0x01],
        "1.2.643.2.2.13.1",
        "id-Gost28147-89-CryptoPro-KeyWrap",
    );

    /// GOST 28147-89 encryption.
    pub const GOST_R28147_GCFB: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x15],
        "1.2.643.2.2.21",
        "id-Gost28147-89",
    );

    /// The test S-boxes.
    pub const GOST28147_89_CRYPTO_PRO_TEST_PARAM_SET: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x00],
        "1.2.643.2.2.31.0",
        "id-Gost28147-89-TestParamSet",
    );

    /// The CryptoPro A S-boxes.
    pub const GOST28147_89_CRYPTO_PRO_A_PARAM_SET: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01],
        "1.2.643.2.2.31.1",
        "id-Gost28147-89-CryptoPro-A-ParamSet",
    );

    /// The CryptoPro B S-boxes.
    pub const GOST28147_89_CRYPTO_PRO_B_PARAM_SET: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x02],
        "1.2.643.2.2.31.2",
        "id-Gost28147-89-CryptoPro-B-ParamSet",
    );

    /// The CryptoPro C S-boxes.
    pub const GOST28147_89_CRYPTO_PRO_C_PARAM_SET: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x03],
        "1.2.643.2.2.31.3",
        "id-Gost28147-89-CryptoPro-C-ParamSet",
    );

    /// The CryptoPro D S-boxes.
    pub const GOST28147_89_CRYPTO_PRO_D_PARAM_SET: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x04],
        "1.2.643.2.2.31.4",
        "id-Gost28147-89-CryptoPro-D-ParamSet",
    );

    /// GOST R 34.10-94 keys.
    pub const GOST_R3410_X94: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x14],
        "1.2.643.2.2.20",
        "id-GostR3410-94",
    );

    /// GOST R 34.10-2001 keys.
    pub const GOST_R3410_X2001: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x13],
        "1.2.643.2.2.19",
        "id-GostR3410-2001",
    );

    /// GOST R 34.10-94 signatures.
    pub const GOST_R3411_X94_WITH_GOST_R3410_X94: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x04],
        "1.2.643.2.2.4",
        "id-GostR3411-94-with-GostR3410-94",
    );

    /// GOST R 34.10-2001 signatures.
    pub const GOST_R3411_X94_WITH_GOST_R3410_X2001: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x03],
        "1.2.643.2.2.3",
        "id-GostR3411-94-with-GostR3410-2001",
    );

    /// The test hash parameters.
    pub const GOST_R3411_X94_TEST_PARAM_SET: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x00],
        "1.2.643.2.2.30.0",
        "id-GostR3411-94-TestParamSet",
    );

    /// The CryptoPro hash parameters.
    pub const GOST_R3411_X94_CRYPTO_PRO_PARAM_SET: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01],
        "1.2.643.2.2.30.1",
        "id-GostR3411-94-CryptoProParamSet",
    );

    /// GOST R 34.10-94 parameter set A.
    pub const GOST_R3410_X94_CRYPTO_PRO_A: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x20, 0x02],
        "1.2.643.2.2.32.2",
        "id-GostR3410-94-CryptoPro-A-ParamSet",
    );

    /// GOST R 34.10-94 parameter set B.
    pub const GOST_R3410_X94_CRYPTO_PRO_B: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x20, 0x03],
        "1.2.643.2.2.32.3",
        "id-GostR3410-94-CryptoPro-B-ParamSet",
    );

    /// GOST R 34.10-94 parameter set C.
    pub const GOST_R3410_X94_CRYPTO_PRO_C: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x20, 0x04],
        "1.2.643.2.2.32.4",
        "id-GostR3410-94-CryptoPro-C-ParamSet",
    );

    /// GOST R 34.10-94 parameter set D.
    pub const GOST_R3410_X94_CRYPTO_PRO_D: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x20, 0x05],
        "1.2.643.2.2.32.5",
        "id-GostR3410-94-CryptoPro-D-ParamSet",
    );

    /// GOST R 34.10-94 exchange set A.
    pub const GOST_R3410_X94_CRYPTO_PRO_XCH_A: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x21, 0x01],
        "1.2.643.2.2.33.1",
        "id-GostR3410-94-CryptoPro-XchA-ParamSet",
    );

    /// GOST R 34.10-94 exchange set B.
    pub const GOST_R3410_X94_CRYPTO_PRO_XCH_B: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x21, 0x02],
        "1.2.643.2.2.33.2",
        "id-GostR3410-94-CryptoPro-XchB-ParamSet",
    );

    /// GOST R 34.10-94 exchange set C.
    pub const GOST_R3410_X94_CRYPTO_PRO_XCH_C: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x21, 0x03],
        "1.2.643.2.2.33.3",
        "id-GostR3410-94-CryptoPro-XchC-ParamSet",
    );

    /// GOST R 34.10-2001 curve A.
    pub const GOST_R3410_X2001_CRYPTO_PRO_A: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01],
        "1.2.643.2.2.35.1",
        "id-GostR3410-2001-CryptoPro-A-ParamSet",
    );

    /// GOST R 34.10-2001 curve B.
    pub const GOST_R3410_X2001_CRYPTO_PRO_B: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x02],
        "1.2.643.2.2.35.2",
        "id-GostR3410-2001-CryptoPro-B-ParamSet",
    );

    /// GOST R 34.10-2001 curve C.
    pub const GOST_R3410_X2001_CRYPTO_PRO_C: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x03],
        "1.2.643.2.2.35.3",
        "id-GostR3410-2001-CryptoPro-C-ParamSet",
    );

    /// GOST R 34.10-2001 exchange curve A.
    pub const GOST_R3410_X2001_CRYPTO_PRO_XCH_A: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00],
        "1.2.643.2.2.36.0",
        "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
    );

    /// GOST R 34.10-2001 exchange curve B.
    pub const GOST_R3410_X2001_CRYPTO_PRO_XCH_B: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x01],
        "1.2.643.2.2.36.1",
        "id-GostR3410-2001-CryptoPro-XchB-ParamSet",
    );

    /// Ephemeral-static Diffie-Hellman.
    pub const GOST_R3410_X2001_CRYPTO_PRO_ESDH: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x60],
        "1.2.643.2.2.96",
        "id-GostR3410-2001-CryptoPro-ESDH",
    );

    /// GOST R 34.10-2001 Diffie-Hellman.
    pub const GOST_R3410_X2001_DH: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x62],
        "1.2.643.2.2.98",
        "id-GostR3410-2001DH",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::GOST_ID,
        Self::GOST_R3411,
        Self::GOST_R3411_HMAC,
        Self::GOST28147_89_NONE_KEY_WRAP,
        Self::GOST28147_89_CRYPTO_PRO_KEY_WRAP,
        Self::GOST_R28147_GCFB,
        Self::GOST28147_89_CRYPTO_PRO_TEST_PARAM_SET,
        Self::GOST28147_89_CRYPTO_PRO_A_PARAM_SET,
        Self::GOST28147_89_CRYPTO_PRO_B_PARAM_SET,
        Self::GOST28147_89_CRYPTO_PRO_C_PARAM_SET,
        Self::GOST28147_89_CRYPTO_PRO_D_PARAM_SET,
        Self::GOST_R3410_X94,
        Self::GOST_R3410_X2001,
        Self::GOST_R3411_X94_WITH_GOST_R3410_X94,
        Self::GOST_R3411_X94_WITH_GOST_R3410_X2001,
        Self::GOST_R3411_X94_TEST_PARAM_SET,
        Self::GOST_R3411_X94_CRYPTO_PRO_PARAM_SET,
        Self::GOST_R3410_X94_CRYPTO_PRO_A,
        Self::GOST_R3410_X94_CRYPTO_PRO_B,
        Self::GOST_R3410_X94_CRYPTO_PRO_C,
        Self::GOST_R3410_X94_CRYPTO_PRO_D,
        Self::GOST_R3410_X94_CRYPTO_PRO_XCH_A,
        Self::GOST_R3410_X94_CRYPTO_PRO_XCH_B,
        Self::GOST_R3410_X94_CRYPTO_PRO_XCH_C,
        Self::GOST_R3410_X2001_CRYPTO_PRO_A,
        Self::GOST_R3410_X2001_CRYPTO_PRO_B,
        Self::GOST_R3410_X2001_CRYPTO_PRO_C,
        Self::GOST_R3410_X2001_CRYPTO_PRO_XCH_A,
        Self::GOST_R3410_X2001_CRYPTO_PRO_XCH_B,
        Self::GOST_R3410_X2001_CRYPTO_PRO_ESDH,
        Self::GOST_R3410_X2001_DH,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
