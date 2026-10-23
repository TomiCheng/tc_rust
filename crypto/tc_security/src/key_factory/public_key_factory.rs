use tc_asn1::{Asn1Error, Decode, DecodingOptions};
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

/// `SubjectPublicKeyInfo` 的 DER 轉成公鑰，同 BC 的 `PublicKeyFactory.CreateKey(byte[])`；結尾多出的
/// bytes 視為錯誤。
pub fn public_key_from_der(der: &[u8]) -> Result<AnyParams, AnyError> {
    let (consumed, info) =
        SubjectPublicKeyInfo::decode(der, &DecodingOptions::default()).map_err(AnyError::new)?;
    if consumed != der.len() {
        return Err(AnyError::new(Asn1Error::TrailingData));
    }
    public_key_from_info(&info)
}

/// `SubjectPublicKeyInfo` 轉成公鑰，同 BC 的 `PublicKeyFactory.CreateKey(SubjectPublicKeyInfo)`：依演算法
/// 的 OID 解讀裡面的公鑰。
pub fn public_key_from_info(info: &SubjectPublicKeyInfo) -> Result<AnyParams, AnyError> {
    #[allow(clippy::match_single_binding, reason = "演算法逐一加入")]
    match info.algorithm().algorithm() {
        _ => Err(AnyError::new(SecurityError::UnknownKeyAlgorithm)),
    }
}
