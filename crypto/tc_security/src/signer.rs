//! 依名稱或 OID 建立簽章器，對應 BC 的 `SignerUtilities`。
//!
//! ```
//! # #[cfg(all(feature = "rsa", feature = "sha256"))] {
//! use tc_security::{generate, signer};
//!
//! // 1. 產生 RSA 金鑰對：私鑰簽章，公鑰驗章。
//! let mut generator = generate::get_by_name("RSA")?.generator();
//! let (public, private) = generator.generate_key_pair()?;
//!
//! // 2. 用私鑰簽，用公鑰驗。
//! let mut rsa = signer::get_by_name("SHA-256withRSA")?.signer();
//! let signature = signer::sign(&mut rsa, &private, b"attack at dawn")?;
//! assert!(signer::verify(&mut rsa, &public, b"attack at dawn", &signature)?);
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod algorithms;
mod any_signer;
mod helpers;
mod signer_entry;
mod table;

pub use algorithms::{algorithms, get_by_name, get_by_oid};
pub use any_signer::AnySigner;
pub use helpers::{sign, verify};
pub use signer_entry::SignerEntry;
