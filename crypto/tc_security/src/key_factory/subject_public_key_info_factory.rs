use tc_asn1::{Encode, EncodingOptions};
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

#[cfg(any(
    feature = "x25519",
    feature = "x448",
    feature = "ed25519",
    feature = "ed448"
))]
use super::cfrg;
use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

/// 公鑰轉成 `SubjectPublicKeyInfo`，同 BC 的 `SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo`；
/// 不是公鑰的參數回傳 `WrongParams`。
pub fn subject_public_key_info(key: &AnyParams) -> Result<SubjectPublicKeyInfo, AnyError> {
    #[allow(clippy::match_single_binding, reason = "沒開任何演算法時只剩 `_`")]
    match key {
        #[cfg(feature = "x25519")]
        AnyParams::X25519Public { key } => Ok(cfrg::subject_public_key_info(cfrg::X25519, key.u())),
        #[cfg(feature = "x448")]
        AnyParams::X448Public { key } => Ok(cfrg::subject_public_key_info(cfrg::X448, key.u())),
        #[cfg(feature = "ed25519")]
        AnyParams::Ed25519Public { key } => {
            Ok(cfrg::subject_public_key_info(cfrg::ED25519, key.a()))
        }
        #[cfg(feature = "ed448")]
        AnyParams::Ed448Public { key } => Ok(cfrg::subject_public_key_info(cfrg::ED448, key.a())),
        _ => Err(AnyError::new(SecurityError::WrongParams)),
    }
}

/// 公鑰轉成 `SubjectPublicKeyInfo` 的 DER。
pub fn public_key_to_der(key: &AnyParams) -> Result<Vec<u8>, AnyError> {
    subject_public_key_info(key)?
        .encode_to_vec(&EncodingOptions::DER)
        .map_err(AnyError::new)
}
