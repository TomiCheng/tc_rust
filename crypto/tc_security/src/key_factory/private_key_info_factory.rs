use tc_asn1::{Encode, EncodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_zeroize::Zeroizing;

#[cfg(any(
    feature = "x25519",
    feature = "x448",
    feature = "ed25519",
    feature = "ed448"
))]
use super::cfrg;
#[cfg(feature = "ec")]
use super::ec;
#[cfg(feature = "rsa")]
use super::rsa;
use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

/// 私鑰轉成 `PrivateKeyInfo`，同 BC 的 `PrivateKeyInfoFactory.CreatePrivateKeyInfo`；不是私鑰的參數回傳
/// `WrongParams`。沒有 CRT 值的 RSA 私鑰也是 `WrongParams`：PKCS#1 的 `RSAPrivateKey` 每個欄位都要有值，
/// BC 在這裡填 0，寫出的不是合法的 PKCS#1。
pub fn private_key_info(key: &AnyParams) -> Result<PrivateKeyInfo, AnyError> {
    #[allow(clippy::match_single_binding, reason = "沒開任何演算法時只剩 `_`")]
    match key {
        #[cfg(feature = "ec")]
        AnyParams::EcPrivate { key } => ec::private_key_info(key),
        #[cfg(feature = "rsa")]
        AnyParams::Rsa {
            key: tc_rsa::RsaKey::Crt(key),
        } => rsa::private_key_info(key),
        #[cfg(feature = "x25519")]
        AnyParams::X25519Private { key } => {
            cfrg::private_key_info(cfrg::X25519, key.k(), key.generate_public_key().u())
        }
        #[cfg(feature = "x448")]
        AnyParams::X448Private { key } => {
            cfrg::private_key_info(cfrg::X448, key.k(), key.generate_public_key().u())
        }
        #[cfg(feature = "ed25519")]
        AnyParams::Ed25519Private { key } => {
            cfrg::private_key_info(cfrg::ED25519, key.k(), key.generate_public_key().a())
        }
        #[cfg(feature = "ed448")]
        AnyParams::Ed448Private { key } => {
            cfrg::private_key_info(cfrg::ED448, key.k(), key.generate_public_key().a())
        }
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
