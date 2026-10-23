use tc_asn1::{Asn1Error, Decode, DecodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;

#[cfg(any(
    feature = "x25519",
    feature = "x448",
    feature = "ed25519",
    feature = "ed448"
))]
use super::cfrg;
#[cfg(feature = "rsa")]
use super::rsa;
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
    #[allow(clippy::match_single_binding, reason = "沒開任何演算法時只剩 `_`")]
    match info.algorithm().algorithm() {
        #[cfg(feature = "rsa")]
        oid if rsa::is_rsa(oid) => Ok(AnyParams::Rsa {
            key: rsa::private_key(info)?,
        }),
        #[cfg(feature = "x25519")]
        oid if *oid == cfrg::X25519 || *oid == cfrg::CRYPTLIB_X25519 => {
            let k = cfrg::private_key(info, true)?;
            let key = tc_cfrg_curves::X25519PrivateKey::new(*k);
            Ok(AnyParams::X25519Private { key })
        }
        #[cfg(feature = "x448")]
        oid if *oid == cfrg::X448 => {
            let k = cfrg::private_key(info, true)?;
            let key = tc_cfrg_curves::X448PrivateKey::new(*k);
            Ok(AnyParams::X448Private { key })
        }
        #[cfg(feature = "ed25519")]
        oid if *oid == cfrg::ED25519 || *oid == cfrg::GNU_ED25519 => {
            let k = cfrg::private_key(info, false)?;
            let key = tc_cfrg_curves::Ed25519PrivateKey::new(*k);
            Ok(AnyParams::Ed25519Private { key })
        }
        #[cfg(feature = "ed448")]
        oid if *oid == cfrg::ED448 => {
            let k = cfrg::private_key(info, false)?;
            let key = tc_cfrg_curves::Ed448PrivateKey::new(*k);
            Ok(AnyParams::Ed448Private { key })
        }
        _ => Err(AnyError::new(SecurityError::UnknownKeyAlgorithm)),
    }
}
