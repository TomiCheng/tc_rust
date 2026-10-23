//! 以密碼加密的方案，對應 BC 的 `PbeUtilities`：依名稱或 OID 找到方案，由密碼、salt 與迭代次數產生
//! cipher 的金鑰與 IV，再交給方案的 cipher。
//!
//! 參數是 salt 與迭代次數本身，不是 BC 的 ASN.1 `PbeParameter`／`Pkcs12PbeParams`；PBES2 的 KDF 與
//! cipher 寫在 ASN.1 裡，還沒有接上。
//!
//! ```
//! # #[cfg(all(feature = "sha1", feature = "desede"))] {
//! use tc_security::{cipher, pbe};
//!
//! let entry = pbe::get_by_name("PBEWithSHAAnd3-KeyTripleDES-CBC")?;
//! let params = entry.generate_cipher_params("password", &[1, 2, 3, 4, 5, 6, 7, 8], 2048)?;
//! let sealed = cipher::encrypt(&mut entry.cipher(), &params, b"secret message")?;
//! assert_eq!(cipher::decrypt(&mut entry.cipher(), &params, &sealed)?, b"secret message");
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod algorithms;
mod pbe_entry;
mod table;

pub use algorithms::{algorithms, get_by_name, get_by_oid};
pub use pbe_entry::PbeEntry;
