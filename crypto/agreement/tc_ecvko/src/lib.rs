//! GOST VKO 金鑰協商（RFC 7836 4.3），移植自 Bouncy Castle 的 `ECVkoAgreement`，實作
//! `tc_agreement` 的 trait。金鑰來自 `tc_ec_key`，雜湊用 `tc_digest` 的 trait。
//!
//! 雙方交換公鑰並約定一個公開的 UKM，以私鑰與對方的公鑰雜湊出同一個秘密：
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_ecvko::{EcVkoAgreement, EcVkoParams};
//! use tc_fp_curve::FpCtCurve;
//! use tc_fp_curve::named_curves::SECP256R1;
//! use tc_gost3411::Gost3411_2012_256Digest;
//!
//! // 雙方用同一條常數時間的曲線與生成點 G；實務上是 GOST R 34.10-2012 的曲線。
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>>::new();
//! generator.init(EcKeyGenerationParams::new(g, &mut rng))?;
//! let (alice_public, alice_private) = generator.generate_key_pair()?;
//! let (bob_public, bob_private) = generator.generate_key_pair()?;
//!
//! // UKM 是公開的隨機值，雙方用同一個。
//! let ukm = vec![0x1d, 0x80, 0x60, 0x3c, 0x85, 0x44, 0xc7, 0x27];
//!
//! let mut alice = EcVkoAgreement::new(Gost3411_2012_256Digest::default());
//! alice.init(&EcVkoParams::new(alice_private, ukm.clone()))?;
//! let mut alice_secret = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(&bob_public, &mut alice_secret)?;
//!
//! let mut bob = EcVkoAgreement::new(Gost3411_2012_256Digest::default());
//! bob.init(&EcVkoParams::new(bob_private, ukm))?;
//! let mut bob_secret = vec![0; bob.agreement_size()];
//! bob.calculate_agreement(&alice_public, &mut bob_secret)?;
//!
//! assert_eq!(alice_secret, bob_secret);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod agreement;
mod error;
mod params;

pub use agreement::EcVkoAgreement;
pub use error::EcVkoError;
pub use params::EcVkoParams;
