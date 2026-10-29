//! SEC 2 curve and SEC 1 scheme identifiers, as Bouncy Castle's
//! `SecObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// SEC 2 curve and SEC 1 scheme identifiers.
///
/// ```
/// use tc_asn1_oid::SecId;
///
/// assert_eq!(SecId::ELLIPTIC_CURVE.dotted(), "1.3.132.0");
/// assert_eq!(
///     SecId::from_oid(&SecId::ELLIPTIC_CURVE.oid()),
///     Some(SecId::ELLIPTIC_CURVE),
/// );
/// ```
pub struct SecId;

impl SecId {
    /// Bouncy Castle's `certicom`.
    pub const CERTICOM: NamedOid = NamedOid::new(&[0x2b, 0x81, 0x04], "1.3.132", "certicom");

    /// Bouncy Castle's `EllipticCurve`.
    pub const ELLIPTIC_CURVE: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00], "1.3.132.0", "EllipticCurve");

    /// Bouncy Castle's `SecT163k1`.
    pub const SEC_T163K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x01], "1.3.132.0.1", "SecT163k1");

    /// Bouncy Castle's `SecT163r1`.
    pub const SEC_T163R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x02], "1.3.132.0.2", "SecT163r1");

    /// Bouncy Castle's `SecT239k1`.
    pub const SEC_T239K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x03], "1.3.132.0.3", "SecT239k1");

    /// Bouncy Castle's `SecT113r1`.
    pub const SEC_T113R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x04], "1.3.132.0.4", "SecT113r1");

    /// Bouncy Castle's `SecT113r2`.
    pub const SEC_T113R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x05], "1.3.132.0.5", "SecT113r2");

    /// Bouncy Castle's `SecP112r1`.
    pub const SEC_P112R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x06], "1.3.132.0.6", "SecP112r1");

    /// Bouncy Castle's `SecP112r2`.
    pub const SEC_P112R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x07], "1.3.132.0.7", "SecP112r2");

    /// Bouncy Castle's `SecP160r1`.
    pub const SEC_P160R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x08], "1.3.132.0.8", "SecP160r1");

    /// Bouncy Castle's `SecP160k1`.
    pub const SEC_P160K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x09], "1.3.132.0.9", "SecP160k1");

    /// Bouncy Castle's `SecP256k1`.
    pub const SEC_P256K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x0a], "1.3.132.0.10", "SecP256k1");

    /// Bouncy Castle's `SecT163r2`.
    pub const SEC_T163R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x0f], "1.3.132.0.15", "SecT163r2");

    /// Bouncy Castle's `SecT283k1`.
    pub const SEC_T283K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x10], "1.3.132.0.16", "SecT283k1");

    /// Bouncy Castle's `SecT283r1`.
    pub const SEC_T283R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x11], "1.3.132.0.17", "SecT283r1");

    /// Bouncy Castle's `SecT131r1`.
    pub const SEC_T131R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x16], "1.3.132.0.22", "SecT131r1");

    /// Bouncy Castle's `SecT131r2`.
    pub const SEC_T131R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x17], "1.3.132.0.23", "SecT131r2");

    /// Bouncy Castle's `SecT193r1`.
    pub const SEC_T193R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x18], "1.3.132.0.24", "SecT193r1");

    /// Bouncy Castle's `SecT193r2`.
    pub const SEC_T193R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x19], "1.3.132.0.25", "SecT193r2");

    /// Bouncy Castle's `SecT233k1`.
    pub const SEC_T233K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x1a], "1.3.132.0.26", "SecT233k1");

    /// Bouncy Castle's `SecT233r1`.
    pub const SEC_T233R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x1b], "1.3.132.0.27", "SecT233r1");

    /// Bouncy Castle's `SecP128r1`.
    pub const SEC_P128R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x1c], "1.3.132.0.28", "SecP128r1");

    /// Bouncy Castle's `SecP128r2`.
    pub const SEC_P128R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x1d], "1.3.132.0.29", "SecP128r2");

    /// Bouncy Castle's `SecP160r2`.
    pub const SEC_P160R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x1e], "1.3.132.0.30", "SecP160r2");

    /// Bouncy Castle's `SecP192k1`.
    pub const SEC_P192K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x1f], "1.3.132.0.31", "SecP192k1");

    /// Bouncy Castle's `SecP224k1`.
    pub const SEC_P224K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x20], "1.3.132.0.32", "SecP224k1");

    /// Bouncy Castle's `SecP224r1`.
    pub const SEC_P224R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x21], "1.3.132.0.33", "SecP224r1");

    /// Bouncy Castle's `SecP384r1`.
    pub const SEC_P384R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x22], "1.3.132.0.34", "SecP384r1");

    /// Bouncy Castle's `SecP521r1`.
    pub const SEC_P521R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x23], "1.3.132.0.35", "SecP521r1");

    /// Bouncy Castle's `SecT409k1`.
    pub const SEC_T409K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x24], "1.3.132.0.36", "SecT409k1");

    /// Bouncy Castle's `SecT409r1`.
    pub const SEC_T409R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x25], "1.3.132.0.37", "SecT409r1");

    /// Bouncy Castle's `SecT571k1`.
    pub const SEC_T571K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x26], "1.3.132.0.38", "SecT571k1");

    /// Bouncy Castle's `SecT571r1`.
    pub const SEC_T571R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x27], "1.3.132.0.39", "SecT571r1");

    /// Bouncy Castle's `SecP192r1`.
    pub const SEC_P192R1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01],
        "1.2.840.10045.3.1.1",
        "SecP192r1",
    );

    /// Bouncy Castle's `SecP256r1`.
    pub const SEC_P256R1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        "1.2.840.10045.3.1.7",
        "SecP256r1",
    );

    /// Bouncy Castle's `secg_scheme`.
    pub const SECG_SCHEME: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x01], "1.3.132.1", "secg_scheme");

    /// Bouncy Castle's `dhSinglePass_cofactorDH_recommendedKDF`.
    pub const DH_SINGLE_PASS_COFACTOR_DH_RECOMMENDED_KDF: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x01],
        "1.3.132.1.1",
        "dhSinglePass_cofactorDH_recommendedKDF",
    );

    /// Bouncy Castle's `dhSinglePass_cofactorDH_specifiedKDF`.
    pub const DH_SINGLE_PASS_COFACTOR_DH_SPECIFIED_KDF: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x02],
        "1.3.132.1.2",
        "dhSinglePass_cofactorDH_specifiedKDF",
    );

    /// Bouncy Castle's `mqvSinglePass_recommendedKDF`.
    pub const MQV_SINGLE_PASS_RECOMMENDED_KDF: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x03],
        "1.3.132.1.3",
        "mqvSinglePass_recommendedKDF",
    );

    /// Bouncy Castle's `mqvSinglePass_specifiedKDF`.
    pub const MQV_SINGLE_PASS_SPECIFIED_KDF: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x04],
        "1.3.132.1.4",
        "mqvSinglePass_specifiedKDF",
    );

    /// Bouncy Castle's `mqvFull_recommendedKDF`.
    pub const MQV_FULL_RECOMMENDED_KDF: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x05],
        "1.3.132.1.5",
        "mqvFull_recommendedKDF",
    );

    /// Bouncy Castle's `mqvFull_specifiedKDF`.
    pub const MQV_FULL_SPECIFIED_KDF: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x06],
        "1.3.132.1.6",
        "mqvFull_specifiedKDF",
    );

    /// Bouncy Castle's `ecies_recommendedParameters`.
    pub const ECIES_RECOMMENDED_PARAMETERS: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x07],
        "1.3.132.1.7",
        "ecies_recommendedParameters",
    );

    /// Bouncy Castle's `ecies_specifiedParameters`.
    pub const ECIES_SPECIFIED_PARAMETERS: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x08],
        "1.3.132.1.8",
        "ecies_specifiedParameters",
    );

    /// Bouncy Castle's `dhSinglePass_stdDH_kdf_schemes`.
    pub const DH_SINGLE_PASS_STD_DH_KDF_SCHEMES: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0b],
        "1.3.132.1.11",
        "dhSinglePass_stdDH_kdf_schemes",
    );

    /// Bouncy Castle's `dhSinglePass_stdDH_sha224kdf_scheme`.
    pub const DH_SINGLE_PASS_STD_DH_SHA224KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0b, 0x00],
        "1.3.132.1.11.0",
        "dhSinglePass_stdDH_sha224kdf_scheme",
    );

    /// Bouncy Castle's `dhSinglePass_stdDH_sha256kdf_scheme`.
    pub const DH_SINGLE_PASS_STD_DH_SHA256KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0b, 0x01],
        "1.3.132.1.11.1",
        "dhSinglePass_stdDH_sha256kdf_scheme",
    );

    /// Bouncy Castle's `dhSinglePass_stdDH_sha384kdf_scheme`.
    pub const DH_SINGLE_PASS_STD_DH_SHA384KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0b, 0x02],
        "1.3.132.1.11.2",
        "dhSinglePass_stdDH_sha384kdf_scheme",
    );

    /// Bouncy Castle's `dhSinglePass_stdDH_sha512kdf_scheme`.
    pub const DH_SINGLE_PASS_STD_DH_SHA512KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0b, 0x03],
        "1.3.132.1.11.3",
        "dhSinglePass_stdDH_sha512kdf_scheme",
    );

    /// Bouncy Castle's `ecdh`.
    pub const ECDH: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x01, 0x0c], "1.3.132.1.12", "ecdh");

    /// Bouncy Castle's `ecmqv`.
    pub const ECMQV: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x01, 0x0d], "1.3.132.1.13", "ecmqv");

    /// Bouncy Castle's `dhSinglePass_cofactorDH_kdf_schemes`.
    pub const DH_SINGLE_PASS_COFACTOR_DH_KDF_SCHEMES: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0e],
        "1.3.132.1.14",
        "dhSinglePass_cofactorDH_kdf_schemes",
    );

    /// Bouncy Castle's `dhSinglePass_cofactorDH_sha224kdf_scheme`.
    pub const DH_SINGLE_PASS_COFACTOR_DH_SHA224KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0e, 0x00],
        "1.3.132.1.14.0",
        "dhSinglePass_cofactorDH_sha224kdf_scheme",
    );

    /// Bouncy Castle's `dhSinglePass_cofactorDH_sha256kdf_scheme`.
    pub const DH_SINGLE_PASS_COFACTOR_DH_SHA256KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0e, 0x01],
        "1.3.132.1.14.1",
        "dhSinglePass_cofactorDH_sha256kdf_scheme",
    );

    /// Bouncy Castle's `dhSinglePass_cofactorDH_sha384kdf_scheme`.
    pub const DH_SINGLE_PASS_COFACTOR_DH_SHA384KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0e, 0x02],
        "1.3.132.1.14.2",
        "dhSinglePass_cofactorDH_sha384kdf_scheme",
    );

    /// Bouncy Castle's `dhSinglePass_cofactorDH_sha512kdf_scheme`.
    pub const DH_SINGLE_PASS_COFACTOR_DH_SHA512KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0e, 0x03],
        "1.3.132.1.14.3",
        "dhSinglePass_cofactorDH_sha512kdf_scheme",
    );

    /// Bouncy Castle's `mqvSinglePass_kdf_schemes`.
    pub const MQV_SINGLE_PASS_KDF_SCHEMES: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0f],
        "1.3.132.1.15",
        "mqvSinglePass_kdf_schemes",
    );

    /// Bouncy Castle's `mqvSinglePass_sha224kdf_scheme`.
    pub const MQV_SINGLE_PASS_SHA224KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0f, 0x00],
        "1.3.132.1.15.0",
        "mqvSinglePass_sha224kdf_scheme",
    );

    /// Bouncy Castle's `mqvSinglePass_sha256kdf_scheme`.
    pub const MQV_SINGLE_PASS_SHA256KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0f, 0x01],
        "1.3.132.1.15.1",
        "mqvSinglePass_sha256kdf_scheme",
    );

    /// Bouncy Castle's `mqvSinglePass_sha384kdf_scheme`.
    pub const MQV_SINGLE_PASS_SHA384KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0f, 0x02],
        "1.3.132.1.15.2",
        "mqvSinglePass_sha384kdf_scheme",
    );

    /// Bouncy Castle's `mqvSinglePass_sha512kdf_scheme`.
    pub const MQV_SINGLE_PASS_SHA512KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x0f, 0x03],
        "1.3.132.1.15.3",
        "mqvSinglePass_sha512kdf_scheme",
    );

    /// Bouncy Castle's `mqvFull_kdf_schemes`.
    pub const MQV_FULL_KDF_SCHEMES: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x10],
        "1.3.132.1.16",
        "mqvFull_kdf_schemes",
    );

    /// Bouncy Castle's `mqvFull_sha224kdf_scheme`.
    pub const MQV_FULL_SHA224KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x10, 0x00],
        "1.3.132.1.16.0",
        "mqvFull_sha224kdf_scheme",
    );

    /// Bouncy Castle's `mqvFull_sha256kdf_scheme`.
    pub const MQV_FULL_SHA256KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x10, 0x01],
        "1.3.132.1.16.1",
        "mqvFull_sha256kdf_scheme",
    );

    /// Bouncy Castle's `mqvFull_sha384kdf_scheme`.
    pub const MQV_FULL_SHA384KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x10, 0x02],
        "1.3.132.1.16.2",
        "mqvFull_sha384kdf_scheme",
    );

    /// Bouncy Castle's `mqvFull_sha512kdf_scheme`.
    pub const MQV_FULL_SHA512KDF_SCHEME: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x10, 0x03],
        "1.3.132.1.16.3",
        "mqvFull_sha512kdf_scheme",
    );

    /// Bouncy Castle's `kdf_algorithms`.
    pub const KDF_ALGORITHMS: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x11],
        "1.3.132.1.17",
        "kdf_algorithms",
    );

    /// Bouncy Castle's `x9_63_kdf`.
    pub const X9_63_KDF: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x11, 0x00],
        "1.3.132.1.17.0",
        "x9_63_kdf",
    );

    /// Bouncy Castle's `nist_concatenation_kdf`.
    pub const NIST_CONCATENATION_KDF: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x11, 0x01],
        "1.3.132.1.17.1",
        "nist_concatenation_kdf",
    );

    /// Bouncy Castle's `tls_kdf`.
    pub const TLS_KDF: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x11, 0x02],
        "1.3.132.1.17.2",
        "tls_kdf",
    );

    /// Bouncy Castle's `ikev2_kdf`.
    pub const IKEV2_KDF: NamedOid = NamedOid::new(
        &[0x2b, 0x81, 0x04, 0x01, 0x11, 0x03],
        "1.3.132.1.17.3",
        "ikev2_kdf",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::CERTICOM,
        Self::ELLIPTIC_CURVE,
        Self::SEC_T163K1,
        Self::SEC_T163R1,
        Self::SEC_T239K1,
        Self::SEC_T113R1,
        Self::SEC_T113R2,
        Self::SEC_P112R1,
        Self::SEC_P112R2,
        Self::SEC_P160R1,
        Self::SEC_P160K1,
        Self::SEC_P256K1,
        Self::SEC_T163R2,
        Self::SEC_T283K1,
        Self::SEC_T283R1,
        Self::SEC_T131R1,
        Self::SEC_T131R2,
        Self::SEC_T193R1,
        Self::SEC_T193R2,
        Self::SEC_T233K1,
        Self::SEC_T233R1,
        Self::SEC_P128R1,
        Self::SEC_P128R2,
        Self::SEC_P160R2,
        Self::SEC_P192K1,
        Self::SEC_P224K1,
        Self::SEC_P224R1,
        Self::SEC_P384R1,
        Self::SEC_P521R1,
        Self::SEC_T409K1,
        Self::SEC_T409R1,
        Self::SEC_T571K1,
        Self::SEC_T571R1,
        Self::SEC_P192R1,
        Self::SEC_P256R1,
        Self::SECG_SCHEME,
        Self::DH_SINGLE_PASS_COFACTOR_DH_RECOMMENDED_KDF,
        Self::DH_SINGLE_PASS_COFACTOR_DH_SPECIFIED_KDF,
        Self::MQV_SINGLE_PASS_RECOMMENDED_KDF,
        Self::MQV_SINGLE_PASS_SPECIFIED_KDF,
        Self::MQV_FULL_RECOMMENDED_KDF,
        Self::MQV_FULL_SPECIFIED_KDF,
        Self::ECIES_RECOMMENDED_PARAMETERS,
        Self::ECIES_SPECIFIED_PARAMETERS,
        Self::DH_SINGLE_PASS_STD_DH_KDF_SCHEMES,
        Self::DH_SINGLE_PASS_STD_DH_SHA224KDF_SCHEME,
        Self::DH_SINGLE_PASS_STD_DH_SHA256KDF_SCHEME,
        Self::DH_SINGLE_PASS_STD_DH_SHA384KDF_SCHEME,
        Self::DH_SINGLE_PASS_STD_DH_SHA512KDF_SCHEME,
        Self::ECDH,
        Self::ECMQV,
        Self::DH_SINGLE_PASS_COFACTOR_DH_KDF_SCHEMES,
        Self::DH_SINGLE_PASS_COFACTOR_DH_SHA224KDF_SCHEME,
        Self::DH_SINGLE_PASS_COFACTOR_DH_SHA256KDF_SCHEME,
        Self::DH_SINGLE_PASS_COFACTOR_DH_SHA384KDF_SCHEME,
        Self::DH_SINGLE_PASS_COFACTOR_DH_SHA512KDF_SCHEME,
        Self::MQV_SINGLE_PASS_KDF_SCHEMES,
        Self::MQV_SINGLE_PASS_SHA224KDF_SCHEME,
        Self::MQV_SINGLE_PASS_SHA256KDF_SCHEME,
        Self::MQV_SINGLE_PASS_SHA384KDF_SCHEME,
        Self::MQV_SINGLE_PASS_SHA512KDF_SCHEME,
        Self::MQV_FULL_KDF_SCHEMES,
        Self::MQV_FULL_SHA224KDF_SCHEME,
        Self::MQV_FULL_SHA256KDF_SCHEME,
        Self::MQV_FULL_SHA384KDF_SCHEME,
        Self::MQV_FULL_SHA512KDF_SCHEME,
        Self::KDF_ALGORITHMS,
        Self::X9_63_KDF,
        Self::NIST_CONCATENATION_KDF,
        Self::TLS_KDF,
        Self::IKEV2_KDF,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
