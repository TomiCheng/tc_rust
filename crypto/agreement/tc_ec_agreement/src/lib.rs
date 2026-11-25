//! 橢圓曲線上的金鑰協商，移植自 Bouncy Castle，實作 `tc_agreement` 的 trait。金鑰來自
//! `tc_ec_key`。
//!
//! - [`EcdhBasicAgreement`]、[`EcdhcBasicAgreement`]：ECDH 與餘因子版 ECDHC（IEEE P1363）。
//! - [`EcMqvBasicAgreement`]：EC-MQV（SEC 1 3.4）。
//! - [`EcVkoAgreement`]：GOST VKO（RFC 7836 4.3）。
//!
//! 有限體上的 DH 不在這裡。
//!
//! # ECDH
//!
//! 雙方只交換公鑰，就在公開通道上得到同一個秘密：
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec_agreement::EcdhBasicAgreement;
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_fp_curve::FpCtCurve;
//! use tc_fp_curve::named_curves::SECP256R1;
//!
//! // 雙方用同一條常數時間的曲線與生成點 G。
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>, _>::new(&mut rng);
//! generator.init(&EcKeyGenerationParams::new(g))?;
//!
//! // 各自產生金鑰對，把公鑰寄給對方。
//! let (alice_public, alice_private) = generator.generate_key_pair()?;
//! let (bob_public, bob_private) = generator.generate_key_pair()?;
//!
//! // Alice 以自己的私鑰配上 Bob 的公鑰……
//! let mut alice = EcdhBasicAgreement::new();
//! alice.init(&alice_private)?;
//! let mut alice_secret = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(&bob_public, &mut alice_secret)?;
//!
//! // ……Bob 反過來，兩人得到同一個秘密，再交給 KDF。
//! let mut bob = EcdhBasicAgreement::new();
//! bob.init(&bob_private)?;
//! let mut bob_secret = vec![0; bob.agreement_size()];
//! bob.calculate_agreement(&alice_public, &mut bob_secret)?;
//!
//! assert_eq!(alice_secret, bob_secret);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # EC-MQV
//!
//! 雙方各有一對長期金鑰，每次協商再各產生一對臨時金鑰，把兩把公鑰都寄給對方：
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec_agreement::{EcMqvBasicAgreement, MqvPrivateParams, MqvPublicParams};
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_fp_curve::FpCtCurve;
//! use tc_fp_curve::named_curves::SECP256R1;
//!
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>, _>::new(&mut rng);
//! generator.init(&EcKeyGenerationParams::new(g))?;
//!
//! // 長期金鑰對事先就有；臨時金鑰對每次協商重新產生。
//! let (alice_static_public, alice_static) = generator.generate_key_pair()?;
//! let (bob_static_public, bob_static) = generator.generate_key_pair()?;
//! let (alice_ephemeral_public, alice_ephemeral) = generator.generate_key_pair()?;
//! let (bob_ephemeral_public, bob_ephemeral) = generator.generate_key_pair()?;
//!
//! let mut alice = EcMqvBasicAgreement::new();
//! alice.init(&MqvPrivateParams::new(alice_static, alice_ephemeral))?;
//! let mut alice_secret = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(
//!     &MqvPublicParams::new(bob_static_public, bob_ephemeral_public),
//!     &mut alice_secret,
//! )?;
//!
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
//!
//! # GOST VKO
//!
//! 雙方交換公鑰並約定一個公開的 UKM，以私鑰與對方的公鑰雜湊出同一個秘密：
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec_agreement::{EcVkoAgreement, EcVkoParams};
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_fp_curve::FpCtCurve;
//! use tc_fp_curve::named_curves::SECP256R1;
//! use tc_gost3411::Gost3411_2012_256Digest;
//!
//! // 實務上是 GOST R 34.10-2012 的曲線。
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>, _>::new(&mut rng);
//! generator.init(&EcKeyGenerationParams::new(g))?;
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

mod ecdh;
mod mqv;
mod vko;

pub use ecdh::{EcdhBasicAgreement, EcdhError, EcdhcBasicAgreement};
pub use mqv::{EcMqvBasicAgreement, EcMqvError, MqvPrivateParams, MqvPublicParams};
pub use vko::{EcVkoAgreement, EcVkoError, EcVkoParams};
