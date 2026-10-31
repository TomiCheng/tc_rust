//! DSA 簽章（FIPS 186），移植自 Bouncy Castle 的 `DsaSigner`，實作 `tc_dsa` 的 `Dsa`；金鑰
//! 來自 `tc_dsa_key`。要簽整則訊息、編碼簽章時，用 `tc_dsa` 的 `DsaDigestSigner` 包起來。

#![no_std]

mod error;
mod signer;

pub use error::DsaSignerError;
pub use signer::DsaSigner;
