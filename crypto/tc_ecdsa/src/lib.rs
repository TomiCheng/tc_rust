#![no_std]
//! 固定寬度短 Weierstrass 曲線的 ECDSA 簽章。
//!
//! 此 crate 接受呼叫端已計算完成的訊息雜湊。簽章使用固定排程的純量乘法、
//! Montgomery 模運算與奇數模反元素；驗證只處理公開資料，因此刻意使用較快的
//! 變動時間演算法。RFC 6979 與外部 `CryptoRng` 兩種 `k` 來源都受支援。
//!
//! 簽章編碼目前只提供定長 `r || s`。DER `SEQUENCE { INTEGER r, INTEGER s }`
//! 需要工作區未具備的 ASN.1 層，因此留待後續整合。

extern crate alloc;

mod encoding;
mod error;
mod k_calculator;
mod key;
mod random_k;
mod rfc6979;
mod scalar;
mod signer;

pub use encoding::{decode_plain, encode_plain};
pub use error::EcdsaError;
pub use k_calculator::KCalculator;
pub use key::{SigningKey, VerifyingKey};
pub use random_k::RandomKCalculator;
pub use rfc6979::HMacKCalculator;
pub use scalar::EcdsaScalar;
pub use signer::{calculate_e, sign_deterministic, sign_randomized, sign_with_calculator, verify};
