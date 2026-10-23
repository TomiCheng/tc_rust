use tc_asn1_x509::cert::SubjectPublicKeyInfo;

#[cfg(any(
    feature = "x25519",
    feature = "x448",
    feature = "ed25519",
    feature = "ed448"
))]
use super::cfrg;
use super::decode::decode_all;
#[cfg(feature = "ec")]
use super::ec;
#[cfg(feature = "rsa")]
use super::rsa;
use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

/// `SubjectPublicKeyInfo` 的 DER 轉成公鑰，同 BC 的 `PublicKeyFactory.CreateKey(byte[])`；結尾多出的
/// bytes 視為錯誤。
pub fn public_key_from_der(der: &[u8]) -> Result<AnyParams, AnyError> {
    public_key_from_info(&decode_all(der)?)
}

/// `SubjectPublicKeyInfo` 轉成公鑰，同 BC 的 `PublicKeyFactory.CreateKey(SubjectPublicKeyInfo)`：依演算法
/// 的 OID 解讀裡面的公鑰。
pub fn public_key_from_info(info: &SubjectPublicKeyInfo) -> Result<AnyParams, AnyError> {
    #[allow(clippy::match_single_binding, reason = "沒開任何演算法時只剩 `_`")]
    match info.algorithm().algorithm() {
        #[cfg(feature = "ec")]
        oid if *oid == ec::ID_EC_PUBLIC_KEY => Ok(AnyParams::EcPublic {
            key: ec::public_key(info)?,
        }),
        #[cfg(feature = "rsa")]
        oid if rsa::is_rsa(oid) => Ok(AnyParams::Rsa {
            key: rsa::public_key(info)?,
        }),
        #[cfg(feature = "x25519")]
        oid if *oid == cfrg::X25519 || *oid == cfrg::CRYPTLIB_X25519 => {
            let key = tc_cfrg_curves::X25519PublicKey::new(cfrg::public_key(info)?);
            Ok(AnyParams::X25519Public { key })
        }
        #[cfg(feature = "x448")]
        oid if *oid == cfrg::X448 => {
            let key = tc_cfrg_curves::X448PublicKey::new(cfrg::public_key(info)?);
            Ok(AnyParams::X448Public { key })
        }
        #[cfg(feature = "ed25519")]
        oid if *oid == cfrg::ED25519 || *oid == cfrg::GNU_ED25519 => {
            let key = tc_cfrg_curves::Ed25519PublicKey::new(cfrg::public_key(info)?);
            Ok(AnyParams::Ed25519Public { key })
        }
        #[cfg(feature = "ed448")]
        oid if *oid == cfrg::ED448 => {
            let key = tc_cfrg_curves::Ed448PublicKey::new(cfrg::public_key(info)?);
            Ok(AnyParams::Ed448Public { key })
        }
        _ => Err(AnyError::new(SecurityError::UnknownKeyAlgorithm)),
    }
}
