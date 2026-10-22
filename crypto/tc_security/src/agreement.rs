//! 依名稱或 OID 建立 key agreement，對應 BC 的 `AgreementUtilities`；共享秘密一律寫成固定長度的 bytes，
//! 同 BC 的 `GetRawAgreement`。
//!
//! ```
//! # #[cfg(feature = "x25519")] {
//! use tc_security::{agreement, generate};
//!
//! // 1. Alice 與 Bob 各產生一組 X25519 金鑰對，交換公鑰。
//! let mut generator = generate::get_by_name("X25519")?.generator();
//! let (alice_public, alice_private) = generator.generate_key_pair()?;
//! let (bob_public, bob_private) = generator.generate_key_pair()?;
//!
//! // 2. 各自用自己的私鑰與對方的公鑰算出共享秘密，兩邊得到同一個值。
//! let entry = agreement::get_by_name("X25519")?;
//! let alice_secret =
//!     agreement::calculate_agreement(&mut entry.agreement(), &alice_private, &bob_public)?;
//! let bob_secret =
//!     agreement::calculate_agreement(&mut entry.agreement(), &bob_private, &alice_public)?;
//! assert_eq!(alice_secret, bob_secret);
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod agreement_entry;
mod algorithms;
mod any_agreement;
#[cfg(feature = "ec")]
mod ecdh;
mod helpers;
mod table;

pub use agreement_entry::AgreementEntry;
pub use algorithms::{algorithms, get_by_name, get_by_oid};
pub use any_agreement::AnyAgreement;
pub use helpers::calculate_agreement;
