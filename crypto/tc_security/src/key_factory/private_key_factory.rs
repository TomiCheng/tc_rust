use tc_asn1::{Asn1Error, Decode, DecodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;

use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

/// PKCS#8 的 DER 轉成私鑰，同 BC 的 `PrivateKeyFactory.CreateKey(byte[])`；結尾多出的 bytes 視為錯誤。
pub fn private_key_from_der(der: &[u8]) -> Result<AnyParams, AnyError> {
    let (consumed, info) =
        PrivateKeyInfo::decode(der, &DecodingOptions::default()).map_err(AnyError::new)?;
    if consumed != der.len() {
        return Err(AnyError::new(Asn1Error::TrailingData));
    }
    private_key_from_info(&info)
}

/// `PrivateKeyInfo` 轉成私鑰，同 BC 的 `PrivateKeyFactory.CreateKey(PrivateKeyInfo)`：依演算法的 OID
/// 解讀裡面的私鑰。
pub fn private_key_from_info(info: &PrivateKeyInfo) -> Result<AnyParams, AnyError> {
    #[allow(clippy::match_single_binding, reason = "演算法逐一加入")]
    match info.algorithm().algorithm() {
        _ => Err(AnyError::new(SecurityError::UnknownKeyAlgorithm)),
    }
}
