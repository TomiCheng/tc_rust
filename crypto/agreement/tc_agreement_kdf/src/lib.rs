//! 先協商、再以 RFC 5753 的 KEK 導出金鑰，移植自 Bouncy Castle 的 `ECDHWithKdfBasicAgreement`、
//! `ECDHCWithKdfBasicAgreement` 與 `ECMqvWithKdfBasicAgreement`。底層協商可以是任何
//! `tc_agreement` 的實作，KDF 通常是 `tc_ecdh_kek` 的 `EcdhKek`。
//!
//! Alice 與 Bob 以 ECDH 協商，直接得到 AES-128 key wrap 用的金鑰：
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_agreement_kdf::{AgreementWithKdf, UkmParams};
//! use tc_asn1_x509::alg::AlgorithmIdentifier;
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_ecdh_kek::EcdhKek;
//! use tc_ecdh_v2::EcdhBasicAgreement;
//! use tc_fp_curve::FpCtCurve;
//! use tc_fp_curve::named_curves::SECP256R1;
//! use tc_sha::Sha256Digest;
//!
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>>::new();
//! generator.init(EcKeyGenerationParams::new(g, &mut rng))?;
//! let (alice_public, alice_private) = generator.generate_key_pair()?;
//! let (bob_public, bob_private) = generator.generate_key_pair()?;
//!
//! // 金鑰給 AES-128 key wrap 用，128 位元；UKM 由寄件人選，隨訊息公開。
//! let aes128_wrap = AlgorithmIdentifier::new("2.16.840.1.101.3.4.1.5".parse()?);
//! let ukm = vec![1, 2, 3, 4, 5, 6, 7, 8];
//! let agreement = || {
//!     let kdf = EcdhKek::new(Sha256Digest::default());
//!     AgreementWithKdf::new(EcdhBasicAgreement::new(), kdf, aes128_wrap.clone(), 128)
//! };
//!
//! let mut alice = agreement();
//! alice.init(&UkmParams::new(alice_private).with_ukm(ukm.clone()))?;
//! let mut alice_key = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(&bob_public, &mut alice_key)?;
//!
//! let mut bob = agreement();
//! bob.init(&UkmParams::new(bob_private).with_ukm(ukm))?;
//! let mut bob_key = vec![0; bob.agreement_size()];
//! bob.calculate_agreement(&alice_public, &mut bob_key)?;
//!
//! assert_eq!(alice_key, bob_key);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod agreement_with_kdf;
mod error;
mod ukm_params;

pub use agreement_with_kdf::AgreementWithKdf;
pub use error::AgreementWithKdfError;
pub use ukm_params::UkmParams;
