use tc_asn1::{Encode, EncodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_zeroize::Zeroizing;

use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

/// 私鑰轉成 `PrivateKeyInfo`，同 BC 的 `PrivateKeyInfoFactory.CreatePrivateKeyInfo`；不是私鑰的參數回傳
/// `WrongParams`。
pub fn private_key_info(key: &AnyParams) -> Result<PrivateKeyInfo, AnyError> {
    #[allow(clippy::match_single_binding, reason = "演算法逐一加入")]
    match key {
        _ => Err(AnyError::new(SecurityError::WrongParams)),
    }
}

/// 私鑰轉成 PKCS#8 的 DER。輸出含有私鑰，所以包在 `Zeroizing` 裡，離開範圍時清除。
pub fn private_key_to_der(key: &AnyParams) -> Result<Zeroizing<Vec<u8>>, AnyError> {
    private_key_info(key)?
        .encode_to_vec(&EncodingOptions::DER)
        .map(Zeroizing::new)
        .map_err(AnyError::new)
}
