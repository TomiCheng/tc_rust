//! RSA 引擎的錯誤型別。

/// 原始 RSA 引擎的錯誤。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaError {
    InvalidModulus,
    InvalidExponent,
    InvalidPrivateExponent,
    InvalidP,
    InvalidQ,
    InvalidDp,
    InvalidDq,
    InvalidQInv,
    EvenModulus,
    EvenPublicExponent,
    InputTooSmall,
    InputTooLarge,
    OutputTooShort,
    FaultyDecryptionOrSigning,
}

impl ::core::fmt::Display for RsaError {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.write_str(match self {
            Self::InvalidModulus => "not a valid RSA modulus",
            Self::InvalidExponent => "not a valid RSA exponent",
            Self::InvalidPrivateExponent => "not a valid RSA private exponent",
            Self::InvalidP => "not a valid RSA P value",
            Self::InvalidQ => "not a valid RSA Q value",
            Self::InvalidDp => "not a valid RSA DP value",
            Self::InvalidDq => "not a valid RSA DQ value",
            Self::InvalidQInv => "not a valid RSA inverse Q value",
            Self::EvenModulus => "RSA modulus is even",
            Self::EvenPublicExponent => "RSA public exponent is even",
            Self::InputTooSmall => "input too small for RSA cipher",
            Self::InputTooLarge => "input too large for RSA cipher",
            Self::OutputTooShort => "output buffer too short for RSA cipher",
            Self::FaultyDecryptionOrSigning => "RSA engine faulty decryption/signing detected",
        })
    }
}

impl ::core::error::Error for RsaError {}
