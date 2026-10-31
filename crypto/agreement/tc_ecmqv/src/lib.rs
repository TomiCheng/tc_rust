//! EC-MQV 金鑰協商（SEC 1 3.4），移植自 Bouncy Castle 的 `ECMqvBasicAgreement`，實作
//! `tc_agreement` 的 trait。金鑰來自 `tc_ec_key`。
//!
//! 雙方各有一對長期金鑰，每次協商再各產生一對臨時金鑰，把兩把公鑰都寄給對方：
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_ecmqv::{EcMqvBasicAgreement, MqvPrivateParams, MqvPublicParams};
//! use tc_fp_curve::FpCtCurve;
//! use tc_fp_curve::named_curves::SECP256R1;
//!
//! // 雙方用同一條常數時間的曲線與生成點 G。
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>>::new();
//! generator.init(EcKeyGenerationParams::new(g, &mut rng))?;
//!
//! // 長期金鑰對事先就有；臨時金鑰對每次協商重新產生。
//! let (alice_static_public, alice_static) = generator.generate_key_pair()?;
//! let (bob_static_public, bob_static) = generator.generate_key_pair()?;
//! let (alice_ephemeral_public, alice_ephemeral) = generator.generate_key_pair()?;
//! let (bob_ephemeral_public, bob_ephemeral) = generator.generate_key_pair()?;
//!
//! // Alice 以自己的兩把私鑰配上 Bob 的兩把公鑰……
//! let mut alice = EcMqvBasicAgreement::new();
//! alice.init(&MqvPrivateParams::new(alice_static, alice_ephemeral))?;
//! let mut alice_secret = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(
//!     &MqvPublicParams::new(bob_static_public, bob_ephemeral_public),
//!     &mut alice_secret,
//! )?;
//!
//! // ……Bob 反過來，兩人得到同一個秘密，再交給 KDF。
//! let mut bob = EcMqvBasicAgreement::new();
//! bob.init(&MqvPrivateParams::new(bob_static, bob_ephemeral))?;
//! let mut bob_secret = vec![0; bob.agreement_size()];
//! bob.calculate_agreement(
//!     &MqvPublicParams::new(alice_static_public, alice_ephemeral_public),
//!     &mut bob_secret,
//! )?;
//!
//! assert_eq!(alice_secret, bob_secret);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod basic_agreement;
mod error;
mod params;

pub use basic_agreement::EcMqvBasicAgreement;
pub use error::EcMqvError;
pub use params::{MqvPrivateParams, MqvPublicParams};
