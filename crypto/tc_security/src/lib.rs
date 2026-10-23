//! 依名稱建立 cipher、MAC 與 digest 的工廠，對應 BC 的 `Org.BouncyCastle.Security`。

pub mod agreement;
mod any_error;
pub mod cipher;
pub mod digest;
pub mod generate;
#[cfg(feature = "key-factory")]
pub mod key_factory;
pub mod mac;
pub mod params;
#[cfg(feature = "pbe")]
pub mod pbe;
mod security_error;
pub mod signer;
pub mod wrap;

pub use any_error::AnyError;
pub use security_error::SecurityError;
