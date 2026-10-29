//! TeleTrusT (Brainpool curves, RIPEMD) identifiers, as Bouncy Castle's
//! `TeleTrusTObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.
//!
//! These names repeat an earlier identifier, so `ALL` and `from_oid` give the
//! first name instead:
//! - `TELETRUST_ALGORITHM`
//! - `TELETRUST_RSA_SIGNATURE_ALGORITHM`
//! - `ECC_BRAINPOOL`

use tc_asn1::{Asn1Oid, NamedOid};

/// TeleTrusT (Brainpool curves, RIPEMD) identifiers.
///
/// ```
/// use tc_asn1_oid::TeletrustId;
///
/// assert_eq!(TeletrustId::ALGORITHM.dotted(), "1.3.36.3");
/// assert_eq!(
///     TeletrustId::from_oid(&TeletrustId::ALGORITHM.oid()),
///     Some(TeletrustId::ALGORITHM),
/// );
/// ```
pub struct TeletrustId;

impl TeletrustId {
    /// Bouncy Castle's `TeleTrusT`.
    pub const TELETRUST: NamedOid = NamedOid::new(&[0x2b, 0x24], "1.3.36", "TeleTrusT");

    /// Bouncy Castle's `algorithm`.
    pub const ALGORITHM: NamedOid = NamedOid::new(&[0x2b, 0x24, 0x03], "1.3.36.3", "algorithm");

    /// Bouncy Castle's `TeleTrusTAlgorithm`, the same identifier as [`Self::ALGORITHM`].
    pub const TELETRUST_ALGORITHM: NamedOid =
        NamedOid::new(&[0x2b, 0x24, 0x03], "1.3.36.3", "TeleTrusTAlgorithm");

    /// Bouncy Castle's `encryptionAlgorithm`.
    pub const ENCRYPTION_ALGORITHM: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x01],
        "1.3.36.3.1",
        "encryptionAlgorithm",
    );

    /// Bouncy Castle's `hashAlgorithm`.
    pub const HASH_ALGORITHM: NamedOid =
        NamedOid::new(&[0x2b, 0x24, 0x03, 0x02], "1.3.36.3.2", "hashAlgorithm");

    /// Bouncy Castle's `signatureAlgorithm`.
    pub const SIGNATURE_ALGORITHM: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03],
        "1.3.36.3.3",
        "signatureAlgorithm",
    );

    /// Bouncy Castle's `signatureScheme`.
    pub const SIGNATURE_SCHEME: NamedOid =
        NamedOid::new(&[0x2b, 0x24, 0x03, 0x04], "1.3.36.3.4", "signatureScheme");

    /// Bouncy Castle's `RipeMD160`.
    pub const RIPEMD160: NamedOid =
        NamedOid::new(&[0x2b, 0x24, 0x03, 0x02, 0x01], "1.3.36.3.2.1", "RipeMD160");

    /// Bouncy Castle's `RipeMD128`.
    pub const RIPEMD128: NamedOid =
        NamedOid::new(&[0x2b, 0x24, 0x03, 0x02, 0x02], "1.3.36.3.2.2", "RipeMD128");

    /// Bouncy Castle's `RipeMD256`.
    pub const RIPEMD256: NamedOid =
        NamedOid::new(&[0x2b, 0x24, 0x03, 0x02, 0x03], "1.3.36.3.2.3", "RipeMD256");

    /// Bouncy Castle's `rsaSignature`.
    pub const RSA_SIGNATURE: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x01],
        "1.3.36.3.3.1",
        "rsaSignature",
    );

    /// Bouncy Castle's `TeleTrusTRsaSignatureAlgorithm`, the same identifier as [`Self::RSA_SIGNATURE`].
    pub const TELETRUST_RSA_SIGNATURE_ALGORITHM: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x01],
        "1.3.36.3.3.1",
        "TeleTrusTRsaSignatureAlgorithm",
    );

    /// Bouncy Castle's `RsaSignatureWithRipeMD160`.
    pub const RSA_SIGNATURE_WITH_RIPEMD160: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x01, 0x02],
        "1.3.36.3.3.1.2",
        "RsaSignatureWithRipeMD160",
    );

    /// Bouncy Castle's `RsaSignatureWithRipeMD128`.
    pub const RSA_SIGNATURE_WITH_RIPEMD128: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x01, 0x03],
        "1.3.36.3.3.1.3",
        "RsaSignatureWithRipeMD128",
    );

    /// Bouncy Castle's `RsaSignatureWithRipeMD256`.
    pub const RSA_SIGNATURE_WITH_RIPEMD256: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x01, 0x04],
        "1.3.36.3.3.1.4",
        "RsaSignatureWithRipeMD256",
    );

    /// Bouncy Castle's `ECSign`.
    pub const EC_SIGN: NamedOid =
        NamedOid::new(&[0x2b, 0x24, 0x03, 0x03, 0x02], "1.3.36.3.3.2", "ECSign");

    /// Bouncy Castle's `ECSignWithSha1`.
    pub const EC_SIGN_WITH_SHA1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x01],
        "1.3.36.3.3.2.1",
        "ECSignWithSha1",
    );

    /// Bouncy Castle's `ECSignWithRipeMD160`.
    pub const EC_SIGN_WITH_RIPEMD160: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x02],
        "1.3.36.3.3.2.2",
        "ECSignWithRipeMD160",
    );

    /// Bouncy Castle's `ECSignWithMD2`.
    pub const EC_SIGN_WITH_MD2: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x03],
        "1.3.36.3.3.2.3",
        "ECSignWithMD2",
    );

    /// Bouncy Castle's `ECSignWithMD5`.
    pub const EC_SIGN_WITH_MD5: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x04],
        "1.3.36.3.3.2.4",
        "ECSignWithMD5",
    );

    /// Bouncy Castle's `ttt_ecg`.
    pub const TTT_ECG: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x05],
        "1.3.36.3.3.2.5",
        "ttt_ecg",
    );

    /// Bouncy Castle's `ecStdCurvesAndGeneration`.
    pub const EC_STD_CURVES_AND_GENERATION: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08],
        "1.3.36.3.3.2.8",
        "ecStdCurvesAndGeneration",
    );

    /// Bouncy Castle's `EccBrainpool`, the same identifier as [`Self::EC_STD_CURVES_AND_GENERATION`].
    pub const ECC_BRAINPOOL: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08],
        "1.3.36.3.3.2.8",
        "EccBrainpool",
    );

    /// Bouncy Castle's `EllipticCurve`.
    pub const ELLIPTIC_CURVE: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01],
        "1.3.36.3.3.2.8.1",
        "EllipticCurve",
    );

    /// Bouncy Castle's `VersionOne`.
    pub const VERSION_ONE: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01],
        "1.3.36.3.3.2.8.1.1",
        "VersionOne",
    );

    /// Bouncy Castle's `BrainpoolP160R1`.
    pub const BRAINPOOL_P160R1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01],
        "1.3.36.3.3.2.8.1.1.1",
        "BrainpoolP160R1",
    );

    /// Bouncy Castle's `BrainpoolP160T1`.
    pub const BRAINPOOL_P160T1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x02],
        "1.3.36.3.3.2.8.1.1.2",
        "BrainpoolP160T1",
    );

    /// Bouncy Castle's `BrainpoolP192R1`.
    pub const BRAINPOOL_P192R1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03],
        "1.3.36.3.3.2.8.1.1.3",
        "BrainpoolP192R1",
    );

    /// Bouncy Castle's `BrainpoolP192T1`.
    pub const BRAINPOOL_P192T1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x04],
        "1.3.36.3.3.2.8.1.1.4",
        "BrainpoolP192T1",
    );

    /// Bouncy Castle's `BrainpoolP224R1`.
    pub const BRAINPOOL_P224R1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05],
        "1.3.36.3.3.2.8.1.1.5",
        "BrainpoolP224R1",
    );

    /// Bouncy Castle's `BrainpoolP224T1`.
    pub const BRAINPOOL_P224T1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x06],
        "1.3.36.3.3.2.8.1.1.6",
        "BrainpoolP224T1",
    );

    /// Bouncy Castle's `BrainpoolP256R1`.
    pub const BRAINPOOL_P256R1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
        "1.3.36.3.3.2.8.1.1.7",
        "BrainpoolP256R1",
    );

    /// Bouncy Castle's `BrainpoolP256T1`.
    pub const BRAINPOOL_P256T1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x08],
        "1.3.36.3.3.2.8.1.1.8",
        "BrainpoolP256T1",
    );

    /// Bouncy Castle's `BrainpoolP320R1`.
    pub const BRAINPOOL_P320R1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09],
        "1.3.36.3.3.2.8.1.1.9",
        "BrainpoolP320R1",
    );

    /// Bouncy Castle's `BrainpoolP320T1`.
    pub const BRAINPOOL_P320T1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0a],
        "1.3.36.3.3.2.8.1.1.10",
        "BrainpoolP320T1",
    );

    /// Bouncy Castle's `BrainpoolP384R1`.
    pub const BRAINPOOL_P384R1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b],
        "1.3.36.3.3.2.8.1.1.11",
        "BrainpoolP384R1",
    );

    /// Bouncy Castle's `BrainpoolP384T1`.
    pub const BRAINPOOL_P384T1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0c],
        "1.3.36.3.3.2.8.1.1.12",
        "BrainpoolP384T1",
    );

    /// Bouncy Castle's `BrainpoolP512R1`.
    pub const BRAINPOOL_P512R1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d],
        "1.3.36.3.3.2.8.1.1.13",
        "BrainpoolP512R1",
    );

    /// Bouncy Castle's `BrainpoolP512T1`.
    pub const BRAINPOOL_P512T1: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0e],
        "1.3.36.3.3.2.8.1.1.14",
        "BrainpoolP512T1",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::TELETRUST,
        Self::ALGORITHM,
        Self::ENCRYPTION_ALGORITHM,
        Self::HASH_ALGORITHM,
        Self::SIGNATURE_ALGORITHM,
        Self::SIGNATURE_SCHEME,
        Self::RIPEMD160,
        Self::RIPEMD128,
        Self::RIPEMD256,
        Self::RSA_SIGNATURE,
        Self::RSA_SIGNATURE_WITH_RIPEMD160,
        Self::RSA_SIGNATURE_WITH_RIPEMD128,
        Self::RSA_SIGNATURE_WITH_RIPEMD256,
        Self::EC_SIGN,
        Self::EC_SIGN_WITH_SHA1,
        Self::EC_SIGN_WITH_RIPEMD160,
        Self::EC_SIGN_WITH_MD2,
        Self::EC_SIGN_WITH_MD5,
        Self::TTT_ECG,
        Self::EC_STD_CURVES_AND_GENERATION,
        Self::ELLIPTIC_CURVE,
        Self::VERSION_ONE,
        Self::BRAINPOOL_P160R1,
        Self::BRAINPOOL_P160T1,
        Self::BRAINPOOL_P192R1,
        Self::BRAINPOOL_P192T1,
        Self::BRAINPOOL_P224R1,
        Self::BRAINPOOL_P224T1,
        Self::BRAINPOOL_P256R1,
        Self::BRAINPOOL_P256T1,
        Self::BRAINPOOL_P320R1,
        Self::BRAINPOOL_P320T1,
        Self::BRAINPOOL_P384R1,
        Self::BRAINPOOL_P384T1,
        Self::BRAINPOOL_P512R1,
        Self::BRAINPOOL_P512T1,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
