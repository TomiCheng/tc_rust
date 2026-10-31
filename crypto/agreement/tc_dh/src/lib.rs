//! Diffie-Hellman 金鑰協商，移植自 Bouncy Castle：`DHBasicAgreement` 實作 `tc_agreement`
//! 的 trait；兩階段的 MTI/A0 協商 `DHAgreement` 見 [`DhAgreement`]。參數與金鑰來自
//! `tc_dh_key`。
//!
//! Alice 與 Bob 在公開的通道上只交換公鑰，就協商出同一個秘密：
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_dh::DhBasicAgreement;
//! use tc_dh_key::standard_groups::rfc3526_2048;
//! use tc_dh_key::{DhKeyGenerationParams, DhKeyPairGenerator};
//!
//! // 雙方用同一組公開的參數：RFC 3526 的 2048 位元群組。
//! let mut rng = rand::rng();
//! let mut generator = DhKeyPairGenerator::new();
//! generator.init(DhKeyGenerationParams::new(rfc3526_2048(), &mut rng))?;
//!
//! // 各自產生金鑰對，把公鑰寄給對方。
//! let (alice_public, alice_private) = generator.generate_key_pair()?;
//! let (bob_public, bob_private) = generator.generate_key_pair()?;
//!
//! // Alice 以自己的私鑰配上 Bob 的公鑰……
//! let mut alice = DhBasicAgreement::new();
//! alice.init(&alice_private)?;
//! let mut alice_secret = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(&bob_public, &mut alice_secret)?;
//!
//! // ……Bob 反過來，兩人得到同一個秘密，再交給 KDF。
//! let mut bob = DhBasicAgreement::new();
//! bob.init(&bob_private)?;
//! let mut bob_secret = vec![0; bob.agreement_size()];
//! bob.calculate_agreement(&alice_public, &mut bob_secret)?;
//!
//! assert_eq!(alice_secret, bob_secret);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod agreement;
mod basic_agreement;
mod error;

pub use agreement::DhAgreement;
pub use basic_agreement::DhBasicAgreement;
pub use error::DhAgreementError;
