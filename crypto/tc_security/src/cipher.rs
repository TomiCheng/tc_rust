//! 依名稱、OID 或演算法組合找到 [`CipherEntry`]，再由它建立 cipher，對應 BC 的 `CipherUtilities`。
//! 參數由呼叫端組成 [`AnyParams`](crate::params::AnyParams)，同 BC 自己建立 `ParametersWithIV` 等參數。
//!
//! ```
//! # #[cfg(feature = "aes")] {
//! use tc_security::cipher;
//! use tc_security::params::AnyParams;
//!
//! let entry = cipher::get_by_name("aes/cbc/pkcs7padding")?;
//! // 每則訊息要用新的隨機 IV；這裡為了簡短用固定值
//! let params = AnyParams::new(vec![0x42; 16]).with_iv(vec![0x24; 16]);
//! let mut any_cipher = entry.cipher();
//!
//! let message = b"attack at dawn";
//! let sealed = cipher::encrypt(&mut any_cipher, &params, message)?;
//! assert_eq!(sealed.len(), 16);
//!
//! assert_eq!(cipher::decrypt(&mut any_cipher, &params, &sealed)?, message);
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod algorithms;
mod any_cipher;
mod any_engine;
mod any_mode;
mod cipher_algorithm;
mod cipher_entry;
mod helpers;
mod mode;
mod padding;
mod table;

pub use algorithms::{algorithms, get, get_by_name, get_by_oid};
pub use any_cipher::AnyCipher;
pub use cipher_algorithm::Algorithm;
pub use cipher_entry::CipherEntry;
pub use helpers::{decrypt, encrypt};
pub use mode::Mode;
pub use padding::Padding;
