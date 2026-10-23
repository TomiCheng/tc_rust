use tc_asn1::{Encode, EncodingOptions};
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

/// 公鑰轉成 `SubjectPublicKeyInfo`，同 BC 的 `SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo`；
/// 不是公鑰的參數回傳 `WrongParams`。
pub fn subject_public_key_info(key: &AnyParams) -> Result<SubjectPublicKeyInfo, AnyError> {
    #[allow(clippy::match_single_binding, reason = "演算法逐一加入")]
    match key {
        _ => Err(AnyError::new(SecurityError::WrongParams)),
    }
}

/// 公鑰轉成 `SubjectPublicKeyInfo` 的 DER。
pub fn public_key_to_der(key: &AnyParams) -> Result<Vec<u8>, AnyError> {
    subject_public_key_info(key)?
        .encode_to_vec(&EncodingOptions::DER)
        .map_err(AnyError::new)
}
