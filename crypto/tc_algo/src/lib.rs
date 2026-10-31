//! 依名稱或 OID 建立演算法的工廠，對應 Bouncy Castle 的 `Org.BouncyCastle.Security`。

pub mod agreement;
pub mod cipher;
pub mod codec;
pub mod digest;
mod error;
pub mod generate;
pub mod kem;
pub mod key;
pub mod mac;
pub mod pbe;
pub mod signer;
pub mod wrap;
pub mod xof;

pub use error::AlgoError;
