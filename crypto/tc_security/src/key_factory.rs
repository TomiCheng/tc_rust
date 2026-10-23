//! 金鑰與 DER 互轉，對應 BC 的 `PrivateKeyFactory`、`PublicKeyFactory`、`PrivateKeyInfoFactory` 與
//! `SubjectPublicKeyInfoFactory`：私鑰是 PKCS#8（RFC 5958）的 `PrivateKeyInfo`，公鑰是 X.509 的
//! `SubjectPublicKeyInfo`。
//!
//! 每個方向都有收 DER 與收 ASN.1 結構兩個版本。演算法要它自己的 feature 開了才能轉換：不認得的
//! OID 回傳 [`SecurityError::UnknownKeyAlgorithm`](crate::SecurityError::UnknownKeyAlgorithm)，
//! 參數不是私鑰（或公鑰）時回傳 [`SecurityError::WrongParams`](crate::SecurityError::WrongParams)。

#[cfg(any(
    feature = "x25519",
    feature = "x448",
    feature = "ed25519",
    feature = "ed448"
))]
mod cfrg;
mod private_key_factory;
mod private_key_info_factory;
mod public_key_factory;
mod subject_public_key_info_factory;

pub use private_key_factory::{private_key_from_der, private_key_from_info};
pub use private_key_info_factory::{private_key_info, private_key_to_der};
pub use public_key_factory::{public_key_from_der, public_key_from_info};
pub use subject_public_key_info_factory::{public_key_to_der, subject_public_key_info};
